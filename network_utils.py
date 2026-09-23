import ipaddress

UNENCRYPTED_PORTS = {
    80: "HTTP",
    23: "Telnet",
    21: "FTP",
    110: "POP3",
    143: "IMAP"
}

def is_unencrypted_port(port):
    """Check if the port uses cleartext protocols."""
    if port in UNENCRYPTED_PORTS:
        return True, UNENCRYPTED_PORTS[port]
    return False, None

def format_alert(alert_type, message):
    """Format console alerts consistently."""
    return f"[ALERT - {alert_type.upper()}] {message}"
