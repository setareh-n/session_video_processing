"""
    plot Flows in two concurrent netflix sessions
"""
import inline as inline
import matplotlib
from matplotlib import pyplot as plt
import scapy.all as sp
import dnslib
import random
import json
import pandas as pd
from numpy import double

YT_DOMAINS = ["googlevideo"]
NF_DOMAINS = ["nflxvideo"]

netflix_ips = []

markers = ['o', 'v', 'x', '*', '^', 'd', '1', '<', '>', '2', '3', '4', '8', 's', 'p', 'P', 'h', 'H', '+', 'X', 'D',
           '|', '_', '.', ',']

def get_netflix_ips(pcap_file):
    with sp.PcapReader(pcap_file) as trace:
        for packet in trace:
            # DNS Packet
            if packet.haslayer(sp.UDP) and packet[sp.UDP].sport == 53:
                # Get DNS data
                raw = sp.raw(packet[sp.UDP].payload)
                # Process the DNS query
                dns = dnslib.DNSRecord.parse(raw)
                # Iterate over answers
                for a in dns.rr:
                    # Check if it's a domain of interest (domain.com)
                    question = str(a.rname)
                    if any(s in question for s in NF_DOMAINS):
                        # Check if it's an answer
                        if a.rtype == 1 or a.rtype == 28:
                            print("Query {} is a Netflix one. Appending IP {} to Netflix IPs".format(question, a.rdata))
                            netflix_ips.append(str(a.rdata))
    print("Netflix IPs: {}".format(netflix_ips))
    return netflix_ips



def counters():
    return {"in_pkts": 0, "out_pkts": 0, "in_bytes": 0, "out_bytes": 0}

FLOW_FILTERS = {'netflix': ["nflxvideo"],
                'youtube': ["googlevideo"],
                }


def get_flow_traffic(pcap_file, netflix_ip_list):
    traffic_data = []
    interval = 1.0
    with sp.PcapReader(pcap_file) as trace:
        start_time = 0
        end_time = -1
        slot_dict = {"start": start_time, "end": end_time, "flows": {}}
        print("Processing slot {}-{}".format(start_time, end_time))
        for packet in trace:
            if not packet.haslayer(sp.IP):
                continue
            if packet.time > end_time:
                # reset your counters
                traffic_data.append(slot_dict)
                if start_time == 0:
                    start_time = packet.time
                else:
                    start_time = end_time
                end_time = start_time + interval
                slot_dict = {"start": start_time, "end": end_time, "flows": {}}
                print("Processing slot {}-{}".format(start_time, end_time))

            # If it belongs to Youtube's traffic
            if packet.haslayer(sp.TCP) and (packet[sp.IP].src in netflix_ip_list or packet[sp.IP].dst in netflix_ip_list):
                key = ''
                # identify the direction
                if packet[sp.IP].src in netflix_ip_list:
                    dir = 1
                    key = "{}:{}:{}:{}:TCP".format(packet[sp.IP].src, packet[sp.TCP].sport, packet[sp.IP].dst,
                                                   packet[sp.TCP].dport)

                elif packet[sp.IP].dst in netflix_ip_list:
                    dir = 0
                    key = "{}:{}:{}:{}:TCP".format(packet[sp.IP].dst, packet[sp.TCP].dport, packet[sp.IP].src,
                                                   packet[sp.TCP].sport)


                if key not in slot_dict["flows"]:
                    slot_dict["flows"][key] = counters()

                if dir == 1:
                    slot_dict["flows"][key]['in_pkts'] += 1
                    slot_dict["flows"][key]['in_bytes'] += packet[sp.IP].len
                else:
                    slot_dict["flows"][key]['out_pkts'] += 1
                    slot_dict["flows"][key]['out_bytes'] += packet[sp.IP].len

            # UPD traffic:
            if packet.haslayer(sp.UDP) and (packet[sp.IP].src in netflix_ip_list or packet[sp.IP].dst in netflix_ip_list):
                key = ''
                # identify the direction
                if packet[sp.IP].src in netflix_ip_list:
                    dir = 1
                    key = "{}:{}:{}:{}:UDP".format(packet[sp.IP].src, packet[sp.UDP].sport, packet[sp.IP].dst,
                                                   packet[sp.UDP].dport)

                elif packet[sp.IP].dst in netflix_ip_list:
                    dir = 0
                    key = "{}:{}:{}:{}:UDP".format(packet[sp.IP].dst, packet[sp.UDP].dport, packet[sp.IP].src,
                                                   packet[sp.UDP].sport)

                if key not in slot_dict["flows"]:
                    slot_dict["flows"][key] = counters()

                if dir == 1:
                    slot_dict["flows"][key]['in_pkts'] += 1
                    slot_dict["flows"][key]['in_bytes'] += packet[sp.IP].len
                else:
                    slot_dict["flows"][key]['out_pkts'] += 1
                    slot_dict["flows"][key]['out_bytes'] += packet[sp.IP].len

    return traffic_data


# split part of traffic mapping to each session_request
def map_flow_session(session_request, traffic):
    flows_session = {}
   # get server ips for each session
    servers = session_request[0]
    for key in servers.keys():
        tabId = key
    server_ip_list = servers[tabId]

    for time_slot in traffic:
        for flowId in time_slot["flows"]:
            #split the flowId
            flowId_items = flowId.split(":")
            ip = flowId_items[0]
            port = flowId_items[3]

            if (ip in server_ip_list) :
                #session_request[1][tabId][ip]    # list of requests for this ip
                #if (port in [d['port'] for d in session_request[1][tabId][ip]]):
                if flowId not in flows_session:
                    flows_session[flowId] = {"time": [], "throughput": []}
                flows_session[flowId]["time"].append(time_slot["end"])
               # flows_session[flowId]["throughput"].append(
               # time_slot["flows"][flowId]["in_bytes"] / ((time_slot["end"] - time_slot["start"]) * 128))

                flows_session[flowId]["throughput"].append(
                    time_slot["flows"][flowId]["in_bytes"] / (double)((time_slot["end"] - time_slot["start"]) * 128) )

    return flows_session



def plot_throughput_per_session_Superold(session1, session2):

    fig, ax = plt.subplots()

    for flowId in session1:
        print("Adding to plot {} {}".format(session1[flowId]["time"], session1[flowId]["throughput"]))

        ax.plot(session1[flowId]["time"], session1[flowId]["throughput"],
                    color="blue", label='Flow' + flowId, linewidth=1)

    for flowId in session2:
        print("Adding to plot {} {}".format(session2[flowId]["time"], session2[flowId]["throughput"]))

        ax.plot(session2[flowId]["time"], session2[flowId]["throughput"],
                    color="red", label='Flow' + flowId, linewidth=1)

    plt.xlabel('time(Second)', fontweight='bold')
    plt.ylabel('Throughput(Kbps)', fontweight='bold')
    ax.legend(loc='upper right')
    fig.suptitle('Two concurrent Netflix sessions', fontsize=14, fontweight='bold')
    plt.savefig("/home/listic/Documents/video_collection/tools/Stored_data/experiment/throughput.png")

    plt.show()


def plot_throughput_per_session_old(session1, session2):

    fig, ax = plt.subplots()

    for flowId in session1:
        print("Adding to plot {} {}".format(session1[flowId]["time"], session1[flowId]["throughput"]))

        ax.plot(session1[flowId]["time"], session1[flowId]["throughput"],
                label='Flow' + flowId, linestyle=':',linewidth= 0.1, marker=random.choice(markers), color='blue')


    for flowId in session2:
        print("Adding to plot {} {}".format(session2[flowId]["time"], session2[flowId]["throughput"]))

        ax.plot(session2[flowId]["time"], session2[flowId]["throughput"],
                label='Flow' + flowId, linestyle='--',linewidth= 0.1, marker=random.choice(markers), color='red')

    plt.xlabel('time(Second)', fontweight='bold')
    plt.ylabel('Throughput(Kbps)', fontweight='bold')
    ax.legend(loc='upper right')
    fig.suptitle('Two concurrent Netflix sessions', fontsize=14, fontweight='bold')
    plt.savefig("/home/listic/Documents/video_collection/tools/Stored_data/experiment/throughput.png")

    plt.show()



def plot_throughput_per_session(session1, session2):

    fig, ax = plt.subplots()
    length = len(markers)
    i= 0
    j=0

    for flowId in session1:
        print("Adding to plot {} {}".format(session1[flowId]["time"], session1[flowId]["throughput"]))

        ax.plot(session1[flowId]["time"], session1[flowId]["throughput"],
                label='Flow' + flowId, linestyle=':',linewidth= 0.1, marker=markers[j], color='blue')
        j+=1

    for flowId in session2:
        print("Adding to plot {} {}".format(session2[flowId]["time"], session2[flowId]["throughput"]))

        ax.plot(session2[flowId]["time"], session2[flowId]["throughput"],
                label='Flow' + flowId, linestyle='--',linewidth= 0.1, marker=markers[i], color='red')
        i+=1

    plt.xlabel('time(Second)', fontweight='bold')
    plt.ylabel('Throughput(Kbps)', fontweight='bold')
    ax.legend(loc='upper right')
    fig.suptitle('Two concurrent Netflix sessions', fontsize=14, fontweight='bold')
    plt.savefig("/home/listic/Documents/video_collection/tools/Stored_data/experiment/throughput.png")

    plt.show()


def make_throughput_session_dictionary(session1, session2):
    # throughputs_dict = {time:{"session1_throughputs":[],"session2_throughputs":[]}}
    throughputs_dict = {}

    for flowId in session1:
        # set the throughputs_dict
        for x in range(len(session1[flowId]["throughput"]) - 1):
            time = int(session1[flowId]["time"][x])
            throughput = session1[flowId]["throughput"][x]

            if time not in throughputs_dict:
                throughputs_dict[time] = {"session1_throughputs":[],"session2_throughputs":[]}
            throughputs_dict[time]["session1_throughputs"].append(throughput)


    for flowId in session2:
        # set the throughputs_dict
        for x in range(len(session2[flowId]["throughput"]) - 1):
            time = int(session2[flowId]["time"][x])
            throughput = session2[flowId]["throughput"][x]

            if time not in throughputs_dict:
                throughputs_dict[time] = {"session1_throughputs": [], "session2_throughputs": []}
            throughputs_dict[time]["session2_throughputs"].append(throughput)

    return throughputs_dict




def get_netflix_port(request):
  port = 0
  headers = request["onCompleted"]["responseHeaders"]
  for header in headers:
    if header["name"] == "X-TCP-Info":
      #"addr=128.93.70.184;port=44038;argp=6.Z1dYAeJyqwS2-JlT4aJRVL56aW46mYnZKFglhC2N5F4" not "X-Session-Info":
      entries = header['value'].split(";")
      for entry in entries:
        kv = entry.split("=")
        if kv[0] == "port":
          return int(kv[1])
  return port

# get a Jsonfile and returns session_requests, a dictionary that key is a tab Id and the value is dic{IP: requests list}
def get_requests(JsonFile):
  with open(JsonFile) as f:
    try:
      fn = json.load(f)
    except:
      print ('Problem processing file requests_history.json')
      return None, None

  servers = {}
  requests = {}
  ports = set()
  session_requests = {}  # group requests based on tabId
  tabs = []

  for val in fn.values():
    try:
      if "nflxvideo" in val["OnBeforeRequestOptions"]['url']:
        service = 'netflix'
      elif "googlevideo" in val["OnBeforeRequestOptions"]['url']:
        service = 'youtube'
      else:
        continue

      tabId = val["onCompleted"]['tabId']
      ip = val["onCompleted"]['ip']

      if tabId not in tabs:
        tabs.append(tabId)
        session_requests[tabId] = {}
        servers[tabId] = []

      if ip not in servers[tabId]:
        servers[tabId].append(ip)
        requests[ip] = []
        session_requests[tabId][ip] = []

      session_requests[tabId][ip].append({
        'start_ts': int(val["OnBeforeRequestOptions"]['timeStamp']),
        'end_ts': int(val["onCompleted"]['timeStamp']),
        'url': val["onCompleted"]['url'],
        'method': val["onCompleted"]['method'],
        'port': 0,
      })

      if service == 'netflix':
        port = get_netflix_port(val)
        session_requests[tabId][ip][-1]['port'] = port
        ports.add(port)

    except KeyError as key:
      continue
    except Exception as e:
      continue

  print("Server IPs: {}".format(servers))
  print("ports : {}".format(ports))
  return  servers, session_requests




#gets an array of throughputs for n sessions per time slot and return the Jain index
def Jain_index_generalized(throughputs):
   """adjust the Jain's fairness index from (0,1] to (0,100] as follows:
    (sum(T_i)) ^ 2 / (n * sum(T_i ^ 2))"""
   #return (100 * (sum(throughputs))^2 / (n * sum(throughputs^2)))
   #devision by zero

   if sum(throughputs) == 0:
       return 0
   else:
    throughputs_pow = [j ** 2 for j in throughputs]
    return (sum(throughputs)**2 /(len(throughputs)* sum(throughputs_pow)))


def Jain_index(x,y):
   if (x==0 and y==0):
       return 0

   else:
    return ( (x + y) ** 2 / (2 *((x ** 2) + (y ** 2))) )


def plot_fairness_metric(throughputs_dict):

    metrics_dic = {}

    # list with two elements, aggregated Throughput for each session
    throughputs = []
    for time in throughputs_dict:
        if len(throughputs_dict[time]["session1_throughputs"])==0 or len(throughputs_dict[time]["session2_throughputs"])==0:
            metrics_dic[time]=0
        else:
            session1_sum_throughput = sum(throughputs_dict[time]["session1_throughputs"])
            session2_sum_throughput = sum(throughputs_dict[time]["session2_throughputs"])
            metrics_dic[time] = Jain_index(session1_sum_throughput,session2_sum_throughput)

    a = sorted(metrics_dic.items(), key=lambda x: x[0])

    xs = [x for x, y in a]
    ys = [y for x, y in a]


    plt.bar(range(len(a)), ys, color='red')
    plt.xlabel('time(Second)', fontweight='bold')
    plt.ylabel('Jain Index', fontweight='bold')
    plt.plot()
    plt.savefig("/home/listic/Documents/video_collection/tools/Stored_data/experiment/jain.png")
    plt.show()



def plot_normal_fairness_metric(throughputs_dict):

    metrics_dic = {}

    # list with two elements, aggregated Throughput for each session
    throughputs = []
    for time in throughputs_dict:
        n = len(throughputs_dict[time]["session1_throughputs"]) + len(throughputs_dict[time]["session2_throughputs"])
        if n == 0:
            metrics_dic[time] = 0
        else:
           throughputs= throughputs_dict[time]["session1_throughputs"]+ throughputs_dict[time]["session2_throughputs"]
           metrics_dic[time] = Jain_index_generalized(throughputs)


    a = sorted(metrics_dic.items(), key=lambda x: x[0])

    xs = [x for x, y in a]
    ys = [y for x, y in a]


    plt.bar(range(len(a)), ys, color='red')
    plt.xlabel('time(Second)', fontweight='bold')
    plt.ylabel('Jain Index', fontweight='bold')
    plt.plot()
    plt.savefig("/home/listic/Documents/video_collection/tools/Stored_data/experiment/jain.png")
    plt.show()

def main():

    netflix_ips = get_netflix_ips("dump.pcap")
    session_request1 = get_requests('1.json')
    session_request2 = get_requests('2.json')

    traffic = get_flow_traffic("dump.pcap", netflix_ips)
    traffic1 = map_flow_session(session_request1, traffic)
    traffic2 = map_flow_session(session_request2, traffic)

    plot_throughput_per_session(traffic1, traffic2)
    throughputs_dictionary = make_throughput_session_dictionary(traffic1, traffic2)
    plot_fairness_metric(throughputs_dictionary)
    plot_normal_fairness_metric(throughputs_dictionary)

if __name__ == "__main__":
    main()










