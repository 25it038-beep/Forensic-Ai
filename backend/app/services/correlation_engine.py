"""
Entity correlation engine for attack graph building
"""

from typing import Dict, List, Any
from ..schemas import GraphNode, GraphLink

def build_attack_graph(scan_context: Dict[str, Any]) -> Dict[str, Any]:
    nodes = []
    links = []
    node_ids = set()

    def add_node(node_id: str, label: str, node_type: str, threat_level: str = "neutral"):
        if node_id in node_ids:
            return
        node_ids.add(node_id)
        nodes.append(GraphNode(id=node_id, label=label, type=node_type, threat_level=threat_level))
    
    def add_link(src: str, tgt: str, rel: str):
        links.append(GraphLink(source=src, target=tgt, relationship=rel))

    sender = scan_context.get("sender", "unknown_sender")
    domain = scan_context.get("domain", "unknown_domain")
    origin_geo = scan_context.get("origin_geo", {})
    ip = origin_geo.get("ip", "unknown_ip") if isinstance(origin_geo, dict) else "unknown_ip"
    asn = origin_geo.get("asn", "unknown_asn") if isinstance(origin_geo, dict) else "unknown_asn"
    url_forensics = scan_context.get("url_forensics", {})
    urls = scan_context.get("urls", [])

    add_node("email", "Email", "email", "warning")
    add_node(sender, sender, "sender", "warning")
    add_node(domain, domain, "domain", "warning")
    add_node(ip, ip, "ip", "warning")
    add_node(asn, asn, "asn", "neutral")

    add_link("email", sender, "from")
    add_link(sender, domain, "domain_of")
    add_link(domain, ip, "resolved_to")
    add_link(ip, asn, "belongs_to")

    if urls:
        for i, u in enumerate(urls[:3]):
            url_id = f"url_{i}"
            add_node(url_id, u, "url", "critical")
            add_link("email", url_id, "contains_link")
            add_link(domain, url_id, "hosts")

    # Threat level adjustments
    risk = scan_context.get("risk_score", 0)
    if risk >= 80:
        for n in nodes:
            if n.type in ["sender","domain","ip"]:
                n.threat_level = "critical"
    elif risk >= 50:
        for n in nodes:
            if n.type in ["sender","domain","ip"]:
                n.threat_level = "warning"

    return {"nodes": [n.model_dump() for n in nodes], "links": [l.model_dump() for l in links]}
