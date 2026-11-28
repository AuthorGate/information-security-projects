from html import escape
from math import cos, pi, sin

from markupsafe import Markup


def svg(graph: dict) -> Markup:
    nodes = graph["nodes"]
    if len(nodes) > 20:
        return Markup("<p>Use the relationship table for this larger inventory.</p>")
    coords = {}
    for i, n in enumerate(nodes):
        angle = 2 * pi * i / len(nodes) - pi / 2
        coords[n["id"]] = (320 + 235 * cos(angle), 160 + 108 * sin(angle))
    items = ['<svg viewBox="0 0 640 325" role="img" aria-label="Inventory relationships">']
    for edge in graph["edges"]:
        x, y = coords[edge["source"]]
        a, b = coords[edge["target"]]
        title = escape(edge["source"] + " → " + edge["target"] + " · " + edge["relation"])
        if (x, y) == (a, b):
            items.append(f'<circle cx="{x+18:.1f}" cy="{y-12:.1f}" r="13" fill="none" stroke="teal"><title>{title}</title></circle>')
        else:
            angle_x, angle_y = a - x, b - y
            length = (angle_x**2 + angle_y**2)**0.5
            u, v = angle_x / length, angle_y / length
            tip_x, tip_y = a - 21*u, b - 21*v
            pts = [(tip_x,tip_y),(tip_x-10*u-5*v,tip_y-10*v+5*u),(tip_x-10*u+5*v,tip_y-10*v-5*u)]
            points = " ".join(f"{px:.1f},{py:.1f}" for px, py in pts)
            items.append(f'<g stroke="teal"><title>{title}</title><line x1="{x}" y1="{y}" x2="{tip_x}" y2="{tip_y}"/><polygon points="{points}" fill="teal"/></g>')
    for n in nodes:
        x, y = coords[n["id"]]
        name = n["id"].split("/")[-1].split(":::")[-1]
        label = escape(name if len(name) < 25 else name[:21] + "…")
        items.append(f'<circle cx="{x}" cy="{y}" r="8" fill="teal"/><text x="{x}" y="{y+24}" text-anchor="middle" font-size="13">{label}</text>')
    items.append("</svg>")
    return Markup("".join(items))
