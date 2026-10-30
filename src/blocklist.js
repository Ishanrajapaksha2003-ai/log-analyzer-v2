// Export approved IPs in common firewall / web server formats.
const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6 = /^[0-9a-fA-F:]+$/;

function isValidIp(ip) {
  if (IPV4.test(ip)) return ip.split('.').every(n => +n >= 0 && +n <= 255);
  return ip.includes(':') && IPV6.test(ip);
}

function exportBlocklist(ips, format) {
  const list = ips.filter(isValidIp);   // never emit unvalidated strings into config files
  switch (format) {
    case 'nginx':
      return list.map(ip => `deny ${ip};`).join('\n') + '\n';
    case 'htaccess':
      return 'Order Allow,Deny\nAllow from all\n' + list.map(ip => `Deny from ${ip}`).join('\n') + '\n';
    case 'iptables':
      return list.map(ip => `iptables -A INPUT -s ${ip} -j DROP`).join('\n') + '\n';
    case 'txt':
    default:
      return list.join('\n') + '\n';
  }
}

module.exports = { exportBlocklist, isValidIp };
