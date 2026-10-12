"""Local browser dashboard for passive network monitoring."""

import argparse
import ipaddress
import json
import sys
import threading
import time
import webbrowser
from collections import Counter, deque
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from runtime_environment import ensure_scapy_environment

ensure_scapy_environment(__file__)

from scapy.all import ARP, DNS, Ether, ICMP, IP, IPv6, TCP, UDP, sniff
from scapy.arch import get_if_addr, get_if_list
from scapy.error import Scapy_Exception

from network_ids import IntrusionDetector, append_alert_log


MAX_PACKETS = 300
MAX_ALERTS = 100
PORT_NAMES = {22: "SSH", 53: "DNS", 80: "HTTP", 123: "NTP", 443: "HTTPS",
              445: "SMB", 3389: "RDP"}
class DashboardState:
    def __init__(self, interface, detector=None, alert_log_path="ids_alerts.jsonl"):
        self.interface = interface
        try:
            self.local_address = get_if_addr(interface)
        except OSError:
            self.local_address = ""
        self.started_at = time.time()
        self.packets = deque(maxlen=MAX_PACKETS)
        self.alerts = deque(maxlen=MAX_ALERTS)
        self.events = deque(maxlen=MAX_ALERTS)
        self.packet_times = deque()
        self.hosts = set()
        self.targeted_ports = Counter()
        self.alert_counts = Counter()
        self.total_packets = 0
        self.total_bytes = 0
        self.error = None
        self.alert_log_error = None
        self.alert_log_path = alert_log_path
        self.lock = threading.Lock()
        self.detector = detector or IntrusionDetector()

    def add_packet(self, packet):
        now = float(getattr(packet, "time", time.time()))
        details = []

        if packet.haslayer(ARP):
            arp = packet[ARP]
            protocol = "ARP"
            source, destination = arp.psrc, arp.pdst
            details.extend((f"Operation: {'request' if arp.op == 1 else 'reply'}",
                            f"Sender MAC: {arp.hwsrc}", f"Target MAC: {arp.hwdst}"))
        else:
            source = destination = "unknown"
            protocol = "Other"
            if packet.haslayer(IP):
                ip = packet[IP]
                source, destination = ip.src, ip.dst
                details.extend((f"IPv4 TTL: {ip.ttl}", f"IP ID: {ip.id}",
                                f"IP protocol number: {ip.proto}"))
                protocol = "IPv4"
            elif packet.haslayer(IPv6):
                ip = packet[IPv6]
                source, destination = ip.src, ip.dst
                details.extend((f"IPv6 hop limit: {ip.hlim}",
                                f"Next header: {ip.nh}"))
                protocol = "IPv6"

        host_source, host_destination = source, destination
        if packet.haslayer(Ether):
            details.extend((f"Source MAC: {packet[Ether].src}",
                            f"Destination MAC: {packet[Ether].dst}"))
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            protocol = "TCP"
            source = f"{source}:{tcp.sport}"
            destination = f"{destination}:{tcp.dport}"
            details.extend((f"TCP flags: {tcp.flags}", f"Sequence: {tcp.seq}",
                            f"Window: {tcp.window}"))
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            protocol = "UDP"
            source = f"{source}:{udp.sport}"
            destination = f"{destination}:{udp.dport}"
            details.append(f"UDP length: {udp.len}")
        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            protocol = "ICMP"
            details.extend((f"ICMP type: {icmp.type}", f"ICMP code: {icmp.code}"))

        if packet.haslayer(DNS):
            dns = packet[DNS]
            protocol = "DNS"
            question = dns.qd
            if question and getattr(question, "qname", None):
                name = question.qname
                if isinstance(name, bytes):
                    name = name.decode("utf-8", errors="replace")
                details.append(f"DNS name: {name.rstrip('.')}")
            details.extend((f"DNS message: {'response' if dns.qr else 'query'}",
                            f"DNS answers: {dns.ancount}"))

        frame_size = len(packet)
        if packet.haslayer(TCP):
            target_port = int(packet[TCP].dport)
        elif packet.haslayer(UDP):
            target_port = int(packet[UDP].dport)
        else:
            target_port = None
        direction = (
            "outbound" if host_source == self.local_address
            else "inbound" if host_destination == self.local_address
            else "other"
        )
        item = {
            "time": datetime.fromtimestamp(now).strftime("%H:%M:%S.%f")[:-3],
            "protocol": protocol,
            "summary": packet.summary(),
            "source": source,
            "destination": destination,
            "size": frame_size,
            "direction": direction,
            "details": details,
        }
        generated_alerts = self.detector.inspect(packet)
        with self.lock:
            self.total_packets += 1
            self.total_bytes += frame_size
            self.packet_times.append((now, direction))
            while self.packet_times and self.packet_times[0][0] < now - 1:
                self.packet_times.popleft()
            new_hosts = {
                address for address in (host_source, host_destination)
                if address and address != "unknown"
            } - self.hosts
            self.hosts.update(new_hosts)
            if target_port is not None:
                self.targeted_ports[target_port] += 1
            self.packets.appendleft(item)
            for address in new_hosts:
                self.events.appendleft({
                    "time": item["time"],
                    "severity": "low",
                    "event": f"New host observed: {address}",
                })
            for alert in generated_alerts:
                severity = alert["severity"]
                self.alerts.appendleft(alert)
                self.alert_counts[severity] += 1
                self.events.appendleft({
                    "time": alert["time"],
                    "severity": severity,
                    "event": f"{alert['rule']}: {alert['message']}",
                })
                if self.alert_log_error is None:
                    try:
                        append_alert_log(alert, self.alert_log_path)
                    except OSError as exc:
                        self.alert_log_error = f"{type(exc).__name__}: {exc}"
                        print(
                            f"Alert log write failed for {self.alert_log_path}: {exc}",
                            file=sys.stderr,
                            flush=True,
                        )

    def snapshot(self):
        with self.lock:
            now = time.time()
            while self.packet_times and self.packet_times[0][0] < now - 1:
                self.packet_times.popleft()
            top_ports = [
                {
                    "port": port,
                    "name": PORT_NAMES.get(port, "Other"),
                    "count": count,
                }
                for port, count in self.targeted_ports.most_common(5)
            ]
            return {
                "interface": self.interface,
                "timestamp": now,
                "uptime_seconds": int(time.time() - self.started_at),
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "packets_per_second": len(self.packet_times),
                "inbound_per_second": sum(
                    direction == "inbound" for _, direction in self.packet_times
                ),
                "outbound_per_second": sum(
                    direction == "outbound" for _, direction in self.packet_times
                ),
                "active_hosts": len(self.hosts),
                "local_address": self.local_address,
                "top_ports": top_ports,
                "alert_counts": {
                    severity: self.alert_counts[severity]
                    for severity in ("critical", "high", "medium", "low")
                },
                "packets": list(self.packets),
                "alerts": list(self.alerts),
                "events": list(self.events),
                "error": self.error,
                "alert_log_error": self.alert_log_error,
            }


PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SENTINEL // Threat Monitor</title>
<style>
:root{color-scheme:dark;--bg:#050806;--panel:#0a100c;--panel2:#101711;--line:#203529;--muted:#879b8d;--text:#b9cbbd;--soft-green:#a9cbb0;--green:#42c879;--cyan:#65dfe0;--red:#ff626b;--orange:#f0a35b;--yellow:#e6ce72;--blue:#91c9eb}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 48% -30%,#14252a 0,transparent 55%),var(--bg);color:var(--text);font:16px/1.5 "Times New Roman",Times,serif}
header{min-height:82px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;padding:10px 3.3vw;background:#0a1116d9;font-family:"Times New Roman",Times,serif}
.brand{display:flex;align-items:center;gap:14px}.mark{font-size:27px;color:var(--green);text-shadow:0 0 8px #42c87944}h1{font-family:"Times New Roman",Times,serif;font-size:26px;line-height:1.1;letter-spacing:.06em;margin:0;color:#e1ece8}.sub{font-family:"Times New Roman",Times,serif;font-size:14px;color:var(--muted);letter-spacing:.04em;text-transform:uppercase}
.headright{display:flex;align-items:center;gap:24px;color:var(--muted);font-family:"Times New Roman",Times,serif;font-size:15px}.live{color:#70d99c;border:1px solid #31543c;border-radius:3px;padding:5px 9px;letter-spacing:.06em;font-size:14px}
main{max-width:1600px;margin:auto;padding:23px 3.3vw 30px}.eyebrow{color:var(--green);letter-spacing:.13em;font-size:10px;text-transform:uppercase;margin:0 0 13px}
.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-bottom:14px}.metric,.panel{background:linear-gradient(145deg,#101a20,#0c1419);border:1px solid var(--line);border-radius:4px}
.metric{padding:15px 17px;min-height:91px}.metric-label,.panel-title{color:var(--muted);font-size:10px;letter-spacing:.11em;text-transform:uppercase}.metric-value{font-size:24px;color:var(--soft-green);margin-top:7px}.metric-note{color:var(--muted);font-size:10px}.accent{color:var(--green)}
.guide{margin-bottom:13px;background:#0d1510;border:1px solid var(--line);border-radius:4px;padding:12px 16px}.guide summary{color:var(--green);cursor:pointer;letter-spacing:.08em;text-transform:uppercase;font-size:10px}.guide-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px 20px;margin-top:12px}.guide-item{color:var(--text);font-size:11px}.guide-item strong{color:var(--soft-green);display:block;font-weight:600;margin-bottom:2px}
.layout{display:grid;grid-template-columns:minmax(0,1.7fr) minmax(310px,.83fr);gap:13px;align-items:start}.stack{display:grid;align-content:start;gap:13px}.panel{padding:15px 17px}.panel-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:13px}.panel-title{color:var(--soft-green)}.tiny{font-size:10px;color:var(--muted)}
.traffic-wrap{height:230px;position:relative;overflow:hidden}
#traffic-chart{width:100%;height:100%;display:block}.legend{display:flex;gap:17px;font-size:10px;color:var(--muted)}.legend i{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:5px}.inbound{background:var(--cyan)}.outbound{background:var(--green)}
.lower{display:grid;grid-template-columns:1fr 1fr;gap:13px}.severity-list,.ports{display:grid;gap:9px}.severity-row,.port-row{display:grid;align-items:center;gap:10px}.severity-row{grid-template-columns:75px 1fr 34px}.port-row{grid-template-columns:44px 1fr 40px}.sev{font-size:10px;text-transform:uppercase}.critical{color:var(--red)}.high{color:var(--orange)}.medium{color:var(--yellow)}.low{color:var(--blue)}.bar{height:5px;background:#1a282e;border-radius:5px;overflow:hidden}.bar i{display:block;height:100%;background:currentColor;border-radius:5px}.port-row .bar i{background:var(--cyan)}
.radar-box{display:flex;align-items:center;justify-content:center;min-height:216px}.radar{width:176px;height:176px;border:1px solid #244334;border-radius:50%;position:relative;background:repeating-radial-gradient(circle,transparent 0 28px,#15271d 29px 30px),linear-gradient(90deg,transparent 49.6%,#17291e 50%,transparent 50.4%),linear-gradient(0deg,transparent 49.6%,#17291e 50%,transparent 50.4%);overflow:hidden}
.radar:before{content:"";position:absolute;inset:0;border-radius:50%;background:conic-gradient(from 0deg,transparent 0deg,#42c8791c 53deg,transparent 70deg);animation:sweep 4s linear infinite}.radar:after{content:"";position:absolute;inset:50% 0 0 50%;background:linear-gradient(135deg,#42c87926,transparent 65%);transform-origin:0 0;animation:sweep 4s linear infinite}
@keyframes sweep{to{transform:rotate(360deg)}}.dot{position:absolute;width:5px;height:5px;background:var(--red);box-shadow:0 0 9px var(--red);border-radius:50%;z-index:2}.dot:nth-child(1){left:62%;top:29%}.dot:nth-child(2){left:36%;top:64%;background:var(--orange);box-shadow:0 0 8px var(--orange)}.dot:nth-child(3){left:72%;top:69%;background:var(--yellow);box-shadow:0 0 8px var(--yellow)}
.events{max-height:370px;overflow:auto}.event{display:grid;grid-template-columns:70px 57px 1fr;gap:9px;padding:8px 0;border-bottom:1px solid #19262b;font-size:11px}.event:last-child{border:0}.event-time{color:var(--muted)}.event-text{color:var(--text)}.empty{padding:22px 0;text-align:center;color:var(--muted)}
.packets{margin-top:13px}.table-wrap{overflow:auto;max-height:260px}table{border-collapse:collapse;width:100%;white-space:nowrap;font-size:11px}td,th{text-align:left;border-bottom:1px solid #1a282d;padding:8px}td{color:var(--text)}th{color:var(--muted);font-weight:400;position:sticky;top:0;background:var(--panel)}.proto{color:var(--cyan)}
footer{padding:14px 0 0;color:var(--muted);font-size:10px;display:flex;justify-content:space-between;gap:12px}
@media(max-width:950px){.layout{grid-template-columns:1fr}.metrics{grid-template-columns:repeat(2,1fr)}}
@media(max-width:600px){header{padding:10px 16px}.headright{gap:8px;font-size:12px}h1{font-size:22px}.sub{font-size:12px}.live{font-size:12px}main{padding:18px 14px}.metrics{gap:8px}.metric{padding:12px}.metric-value{font-size:20px}.lower,.guide-grid{grid-template-columns:1fr}.event{grid-template-columns:62px 50px 1fr;font-size:10px}footer{flex-direction:column}}
</style>
</head>
<body>
<header><div class="brand"><div class="mark">◈</div><div><h1>SENTINEL<span style="color:var(--green)">//</span> SOC</h1><div class="sub">Security operations · live threat monitor</div></div></div><div class="headright"><span id="iface">iface: —</span><span>mode: passive</span><span id="clock">--:--:--</span><span class="live" id="connection">CONNECTING</span></div></header>
<main>
<p class="eyebrow">Live telemetry · this session · observed data</p>
<section class="metrics">
<div class="metric"><div class="metric-label">Packets / sec</div><div class="metric-value" id="pps">0</div><div class="metric-note">rolling 1-second rate</div></div>
<div class="metric"><div class="metric-label">IDS alerts · session</div><div class="metric-value" id="alert-total">0</div><div class="metric-note">heuristic detections · not blocked</div></div>
<div class="metric"><div class="metric-label">Unique hosts observed</div><div class="metric-value" id="hosts">0</div><div class="metric-note" id="local-ip">local address: —</div></div>
<div class="metric"><div class="metric-label">Monitoring uptime</div><div class="metric-value" id="uptime">0s</div><div class="metric-note" id="packet-total">0 packets observed</div></div>
</section>
<section class="panel packets"><div class="panel-head"><div class="panel-title">Recently captured packets</div><span class="tiny">Scapy packet summary · payload contents are not displayed or stored</span></div><div class="table-wrap"><table><thead><tr><th>Time</th><th>Protocol</th><th>Direction</th><th>Source</th><th>Destination</th><th>Size</th><th>Captured packet summary</th></tr></thead><tbody id="packet-rows"></tbody></table></div></section>
<details class="guide" open><summary>Quick guide · simple explanations</summary><div class="guide-grid">
<div class="guide-item"><strong>Packets per second</strong>How many network packets this computer saw in the last second. A packet is one small piece of network communication.</div>
<div class="guide-item"><strong>In / outbound lines</strong>Packets addressed to this computer / sent by this computer, based on the selected network interface's IP address.</div>
<div class="guide-item"><strong>Unique IPs observed</strong>Different source or destination IP addresses seen since monitoring started. These can include internet servers; this is not a count of people or devices in your home.</div>
<div class="guide-item"><strong>Targeted ports</strong>Destination service numbers seen in packets. For example, 443 is commonly used for secure web traffic. A port count is traffic observed, not a vulnerability.</div>
<div class="guide-item"><strong>Alert severity</strong>A simple priority label assigned by this demo to its pattern rules. An alert is a clue to check, not proof of an attack.</div>
<div class="guide-item"><strong>Passive monitoring</strong>This program watches traffic and reports patterns. It does not block connections, identify an attacker, or confirm that a threat succeeded.</div>
</div></details>
<div class="layout">
<div class="stack">
<section class="panel"><div class="panel-head"><div class="panel-title">Network traffic</div><div class="legend"><span><i class="inbound"></i>inbound</span><span><i class="outbound"></i>outbound</span><span class="tiny">rolling samples · packets/sec</span></div></div><div class="traffic-wrap"><canvas id="traffic-chart"></canvas></div></section>
<div class="lower">
<section class="panel"><div class="panel-head"><div class="panel-title">Alerts by severity</div><span class="tiny">session totals</span></div><div class="severity-list" id="severity-list"></div></section>
<section class="panel"><div class="panel-head"><div class="panel-title">Top targeted ports</div><span class="tiny">observed traffic</span></div><div class="ports" id="ports-list"></div></section>
</div>
</div>
<div class="stack">
<section class="panel"><div class="panel-head"><div class="panel-title">Threat radar</div><span class="tiny">visual demo · 4s sweep</span></div><div class="radar-box"><div class="radar"><i class="dot"></i><i class="dot"></i><i class="dot"></i></div></div><div class="tiny" style="text-align:center">Decorative animation · markers are not live threat locations</div></section>
<section class="panel"><div class="panel-head"><div class="panel-title">Live event log</div><span class="tiny">newest first</span></div><div class="events" id="events"><div class="empty">Waiting for observed events…</div></div></section>
</div>
</div>
<footer><span>Educational demo: session-only observations, not a full network inventory or verified security verdict. Radar is decorative; no traffic is blocked.</span><span>Capture only networks you are authorized to monitor.</span></footer>
</main>
<script>
const number=n=>new Intl.NumberFormat().format(n);
const history=[];
function drawTraffic(){
 const canvas=document.getElementById('traffic-chart'),rect=canvas.getBoundingClientRect(),ratio=window.devicePixelRatio||1;
 if(!rect.width||!rect.height)return;
 canvas.width=rect.width*ratio;canvas.height=rect.height*ratio;
 const ctx=canvas.getContext('2d');ctx.scale(ratio,ratio);
 const w=rect.width,h=rect.height,left=43,right=12,top=10,bottom=28;
 const plotW=w-left-right,plotH=h-top-bottom,now=Date.now(),windowMs=60000;
 const peak=Math.max(0,...history.flatMap(sample=>[sample.inbound,sample.outbound]));
 const roughMax=Math.max(5,peak),magnitude=Math.pow(10,Math.floor(Math.log10(roughMax)));
 const stepBase=roughMax/magnitude<=2?0.5:roughMax/magnitude<=5?1:2;
 const step=stepBase*magnitude,maxValue=Math.ceil(roughMax/step)*step;
 ctx.font='12px "Times New Roman", Times, serif';ctx.textBaseline='middle';
 for(let tick=0;tick<=maxValue;tick+=step){
  const y=top+plotH-(tick/maxValue)*plotH;
  ctx.beginPath();ctx.strokeStyle='#203039';ctx.lineWidth=1;ctx.moveTo(left,y);ctx.lineTo(w-right,y);ctx.stroke();
  ctx.fillStyle='#72858c';ctx.textAlign='right';ctx.fillText(number(tick),left-8,y);
 }
 for(const seconds of [60,30,0]){
  const x=left+plotW*(1-seconds/60);
  ctx.beginPath();ctx.strokeStyle='#172329';ctx.moveTo(x,top);ctx.lineTo(x,top+plotH);ctx.stroke();
  ctx.fillStyle='#72858c';ctx.textAlign=seconds===60?'left':seconds===0?'right':'center';
  ctx.fillText(seconds===0?'now':`${seconds}s`,x,h-10);
 }
 ctx.save();ctx.beginPath();ctx.rect(left,top,plotW,plotH);ctx.clip();
 for(const [key,color] of [['inbound','#65dfe0'],['outbound','#42c879']]){
  const visible=history.filter(sample=>sample.at>=now-windowMs);
  if(!visible.length)continue;
  const points=visible.map(sample=>({
   x:left+plotW*(1-(now-sample.at)/windowMs),
   y:top+plotH-(sample[key]/maxValue)*plotH,
  }));
  const baseline=top+plotH;
  ctx.beginPath();ctx.moveTo(points[0].x,baseline);
  for(const point of points)ctx.lineTo(point.x,point.y);
  ctx.lineTo(points[points.length-1].x,baseline);ctx.closePath();
  ctx.globalAlpha=.1;ctx.fillStyle=color;ctx.fill();ctx.globalAlpha=1;
  ctx.beginPath();points.forEach((point,index)=>index===0?ctx.moveTo(point.x,point.y):ctx.lineTo(point.x,point.y));
  ctx.strokeStyle=color;ctx.lineWidth=2;ctx.lineJoin='round';ctx.lineCap='round';ctx.stroke();
  const latest=points[points.length-1];
  if(latest.x>left+plotW*.9){ctx.beginPath();ctx.arc(latest.x,latest.y,3,0,Math.PI*2);ctx.fillStyle=color;ctx.fill()}
 }
 ctx.restore();
}
function render(data){
 document.getElementById('iface').textContent='iface: '+data.interface;
 document.getElementById('clock').textContent=new Date().toLocaleTimeString();
 const connection=document.getElementById('connection');
 connection.textContent=data.error?'CAPTURE ERROR':data.alert_log_error?'LOG ERROR':'● LIVE';
 connection.style.color=(data.error||data.alert_log_error)?'#ff626b':'#70d99c';
 connection.title=data.error||data.alert_log_error||'Monitoring and alert logging active';
 document.getElementById('pps').textContent=number(data.packets_per_second);
 document.getElementById('alert-total').textContent=number(Object.values(data.alert_counts).reduce((a,b)=>a+b,0));
 document.getElementById('hosts').textContent=number(data.active_hosts);
 document.getElementById('local-ip').textContent='local address: '+(data.local_address||'unavailable');
 document.getElementById('uptime').textContent=number(data.uptime_seconds)+'s';
 document.getElementById('packet-total').textContent=number(data.total_packets)+' packets observed';
 const sampleTime=(data.timestamp||Date.now()/1000)*1000;
 if(!history.length||sampleTime>history[history.length-1].at){
  history.push({at:sampleTime,inbound:data.inbound_per_second,outbound:data.outbound_per_second});
 }
 while(history.length&&history[0].at<sampleTime-60000)history.shift();
 drawTraffic();
 const severity=document.getElementById('severity-list');severity.replaceChildren();
 const entries=Object.entries(data.alert_counts),max=Math.max(1,...entries.map(item=>item[1]));
 for(const [name,count] of entries){const row=document.createElement('div');row.className='severity-row '+name;const label=document.createElement('span');label.className='sev';label.textContent=name;const track=document.createElement('span');track.className='bar';const fill=document.createElement('i');fill.style.width=(count/max*100)+'%';track.append(fill);const total=document.createElement('span');total.textContent=number(count);row.append(label,track,total);severity.append(row)}
 const ports=document.getElementById('ports-list');ports.replaceChildren();
 if(!data.top_ports.length){ports.innerHTML='<div class="empty">No transport ports observed yet.</div>'}
 else{const maxPort=Math.max(1,...data.top_ports.map(p=>p.count));for(const item of data.top_ports){const row=document.createElement('div');row.className='port-row';const port=document.createElement('span');port.textContent=item.port;const track=document.createElement('span');track.className='bar';const fill=document.createElement('i');fill.style.width=(item.count/maxPort*100)+'%';track.append(fill);const total=document.createElement('span');total.textContent=number(item.count);row.title=item.name;row.append(port,track,total);ports.append(row)}}
 const events=document.getElementById('events');events.replaceChildren();
 if(!data.events.length){const empty=document.createElement('div');empty.className='empty';empty.textContent='No events observed yet.';events.append(empty)}
 for(const event of data.events){const row=document.createElement('div');row.className='event';const time=document.createElement('span');time.className='event-time';time.textContent=event.time;const severityLabel=document.createElement('span');severityLabel.className='sev '+event.severity;severityLabel.textContent=event.severity;const text=document.createElement('span');text.className='event-text';text.textContent=event.event;row.append(time,severityLabel,text);events.append(row)}
 const rows=document.getElementById('packet-rows');rows.replaceChildren();
 for(const packet of data.packets.slice(0,80)){const row=document.createElement('tr');for(const text of [packet.time,packet.protocol,packet.direction,packet.source,packet.destination,number(packet.size)+' B',packet.summary]){const cell=document.createElement('td');cell.textContent=text;if(text===packet.protocol)cell.className='proto';row.append(cell)}rows.append(row)}
}
async function poll(){try{const response=await fetch('/api/status',{cache:'no-store'});if(!response.ok)throw new Error('HTTP '+response.status);render(await response.json())}catch(error){document.getElementById('connection').textContent='API ERROR';document.getElementById('connection').title=error.message}finally{setTimeout(poll,1000)}}
window.addEventListener('resize',drawTraffic);poll();
</script>
</body></html>"""


def make_handler(state):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/":
                body = PAGE.encode("utf-8")
                content_type = "text/html; charset=utf-8"
            elif self.path == "/api/status":
                body = json.dumps(state.snapshot()).encode("utf-8")
                content_type = "application/json; charset=utf-8"
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format, *_args):
            _ = (_format, _args)
            return

    return Handler


def get_capture_interface(interfaces=None):
    candidates = get_if_list() if interfaces is None else interfaces
    fallback_interface = None
    for name in candidates:
        if "loopback" in name.lower():
            continue
        try:
            address = get_if_addr(name)
            if not address:
                continue
            parsed_address = ipaddress.ip_address(address)
        except (OSError, Scapy_Exception, ValueError):
            continue
        if parsed_address.is_unspecified or parsed_address.is_loopback:
            continue
        if fallback_interface is None:
            fallback_interface = name
        if not parsed_address.is_link_local:
            return name
    return fallback_interface


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Launch a loopback-only browser dashboard for passive network monitoring."
    )
    parser.add_argument("-i", "--interface", help="network interface to monitor")
    parser.add_argument("--port", type=int, default=8765, help="local dashboard port (default: 8765)")
    parser.add_argument("--list-interfaces", action="store_true", help="list interfaces and exit")
    parser.add_argument("--alert-log", default="ids_alerts.jsonl",
                        help="append detected alerts as JSON Lines here (default: ids_alerts.jsonl)")
    parser.add_argument("--window-seconds", type=float, default=10.0,
                        help="detection time window in seconds (default: 10)")
    parser.add_argument("--port-scan-threshold", type=int, default=15,
                        help="distinct destination ports before a scan alert (default: 15)")
    parser.add_argument("--syn-flood-threshold", type=int, default=100,
                        help="SYN packets per destination before an alert (default: 100)")
    parser.add_argument("--icmp-flood-threshold", type=int, default=30,
                        help="ICMP packets per source before an alert (default: 30)")
    args = parser.parse_args(argv)

    if args.list_interfaces:
        for interface in get_if_list():
            try:
                address = get_if_addr(interface)
            except OSError:
                address = "unknown"
            print(f"{interface}  IPv4={address}")
        return 0
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    if args.window_seconds <= 0:
        parser.error("--window-seconds must be greater than zero")
    if min(args.port_scan_threshold, args.syn_flood_threshold, args.icmp_flood_threshold) < 1:
        parser.error("detection thresholds must be greater than zero")

    interfaces = get_if_list()
    interface = args.interface
    if interface is None:
        interface = get_capture_interface(interfaces)
    elif interface not in interfaces:
        print(
            f"Unknown interface: {interface}. Run with --list-interfaces to see valid names.",
            file=sys.stderr,
        )
        return 2
    if interface not in interfaces:
        print("No valid capture interface found. Run with --list-interfaces.", file=sys.stderr)
        return 1

    detector = IntrusionDetector(
        window_seconds=args.window_seconds,
        port_scan_threshold=args.port_scan_threshold,
        syn_flood_threshold=args.syn_flood_threshold,
        icmp_flood_threshold=args.icmp_flood_threshold,
    )
    state = DashboardState(interface, detector, args.alert_log)

    def capture():
        try:
            sniff(iface=interface, prn=state.add_packet, store=False)
        except (OSError, Scapy_Exception, ValueError) as exc:
            with state.lock:
                state.error = f"{type(exc).__name__}: {exc}"
            print(f"Packet capture failed: {exc}", file=sys.stderr, flush=True)

    capture_thread = threading.Thread(target=capture, name="packet-capture", daemon=True)
    capture_thread.start()
    try:
        server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(state))
    except OSError as exc:
        print(f"Could not start dashboard on port {args.port}: {exc}", file=sys.stderr)
        return 1

    url = f"http://127.0.0.1:{args.port}/"
    print(f"Monitoring {interface}. Dashboard: {url}", flush=True)
    print("This dashboard is available only on this computer. Press Ctrl+C to stop.", flush=True)
    webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping dashboard.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())