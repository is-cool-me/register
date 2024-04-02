var regNone = NewRegistrar("none");
var providerCf = DnsProvider(NewDnsProvider("cloudflare"));

var proxy = {
    off: { cloudflare_proxy: "off" },
    on: { cloudflare_proxy: "on" }
};

function getDomainsList(filesPath) {
    var result = [];
    var files = glob.apply(null, [filesPath, true, ".json"]);

    for (var i = 0; i < files.length; i++) {
        var basename = files[i].split("/").reverse()[0];
        var name = basename.split(".")[0];

        result.push({ name: name, data: require(files[i]) });
    }

    return result;
}

var domains = getDomainsList("./domains");

var commit = {};

for (var idx in domains) {
    var domainData = domains[idx].data;
    var proxyState = domainData.proxied ? proxy.on : proxy.off;

    if (!commit[domainData.domain]) commit[domainData.domain] = [];

    var owner = domainData.owner;
    var ownerInfo = owner ? (owner.username ? owner.username : '') + ' ' + (owner.email ? '<' + owner.email + '>' : '') : '';

    console.log("Configuring domain: " + domainData.subdomain + "." + domainData.domain + ", Owner: " + ownerInfo);

    if (domainData.records && domainData.records.A) {
        for (var a in domainData.records.A) {
            commit[domainData.domain].push(A(domainData.subdomain, IP(domainData.records.A[a]), proxyState));
        }
    }

    if (domainData.records && domainData.records.AAAA) {
        for (var aaaa in domainData.records.AAAA) {
            commit[domainData.domain].push(AAAA(domainData.subdomain, domainData.records.AAAA[aaaa], proxyState));
        }
    }

    if (domainData.records && domainData.records.CNAME) {
        commit[domainData.domain].push(CNAME(domainData.subdomain, domainData.records.CNAME + ".", proxyState));
    }

    if (domainData.records && domainData.records.MX) {
        for (var mx in domainData.records.MX) {
            commit[domainData.domain].push(MX(domainData.subdomain, domainData.records.MX[mx].priority, domainData.records.MX[mx].value + "."));
        }
    }

    if (domainData.records && domainData.records.NS) {
        for (var ns in domainData.records.NS) {
            commit[domainData.domain].push(NS(domainData.subdomain, domainData.records.NS[ns] + "."));
        }
    }

    if (domainData.records && domainData.records.TXT) {
        var txtRecords = domainData.records.TXT;
        if (Array.isArray(txtRecords)) {
            // If TXT records are in the format of an array
            for (var txtRecord of txtRecords) {
                if (typeof txtRecord === 'string') {
                    // If txtRecord is a string, push it directly
                    commit[domainData.domain].push(TXT(domainData.subdomain, txtRecord));
                } else {
                    // If txtRecord is an object with name and value properties
                    var txtName = txtRecord.name === "@" ? domainData.subdomain : txtRecord.name + "." + domainData.subdomain;
                    commit[domainData.domain].push(TXT(txtName, txtRecord.value));
                }
            }
        } else if (typeof txtRecords === 'string') {
            // If TXT records are in the format of a single string
            commit[domainData.domain].push(TXT(domainData.subdomain, txtRecords));
        }
    }
}

for (var domainName in commit) {
    D(domainName, regNone, providerCf, commit[domainName]);
}
