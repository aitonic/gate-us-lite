from gate_us_lite.models import Candidate, OpenVPNProfile

CA = "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----"


def candidate(ip: str, port: int = 1194, proto: str = "udp") -> Candidate:
    profile = OpenVPNProfile(ip, port, proto, CA, username="vpn", password="vpn")
    return Candidate("vpngate", "vpngate", ip, "US", "", ip, ip, profile)
