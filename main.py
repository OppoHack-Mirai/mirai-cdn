import hashlib
import math
import os
import random
import shutil
import sys
import threading
import time
from abc import abstractmethod
from collections import defaultdict
from typing import Optional

import firebase_admin
import ipinfo
import requests
from firebase_admin import credentials
from firebase_admin import firestore
from flask import Flask, request, jsonify, abort, redirect, send_file
from google.cloud.firestore_v1 import ArrayUnion
from requests import HTTPError


class CDNProgram:
    @abstractmethod
    def start(self):
        pass


flask_app = Flask("Mirai")
cnc_node = None  # type: Optional[CDNCNCNode]


def get_time() -> int:
    return int(time.time())


def get_elapsed(previous_time) -> int:
    return get_time() - previous_time


def haversine(lat1, lon1, lat2, lon2):
    lon1, lat1, lon2, lat2 = map(math.radians, [lon1, lat1, lon2, lat2])
    d_lon = lon2 - lon1
    d_lat = lat2 - lat1
    a = math.sin(d_lat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(d_lon / 2) ** 2
    c = 2 * math.asin(math.sqrt(a))
    r = 6371
    return c * r


# Map from str (ip address) to dict (latitude and longitude key) of location
ip_address_to_location_map = {}

# Percent of nodes that must contain a file
FILE_REDUNDANCY_THRESHOLD = 0.60


# Command node server (connects to end nodes)
class CDNCNCNode(CDNProgram):
    def __init__(self):
        global cnc_node
        self.db = None
        cnc_node = self

        if len(sys.argv) < 3:
            print("Please provide ip info token as second argument")
            exit(1)
        ip_info_token = sys.argv[2]
        self.ip_info = ipinfo.getHandler(ip_info_token)

    def start(self):
        global flask_app

        # Connect to firebase
        cred = credentials.Certificate("firebase_key.json")
        fb_app = firebase_admin.initialize_app(cred)
        self.db = firestore.client(fb_app)
        print("Connected to firebase.")

        daemon = threading.Thread(target=self.heartbeat_periodic, daemon=True, name='Heartbeats')
        daemon.start()
        daemon = threading.Thread(target=self.file_health_periodic, daemon=True, name='File Health')
        daemon.start()

        print("Command node started.")
        flask_app.run(host='0.0.0.0', port=9981)

    def heartbeat_periodic(self):
        while True:
            self.check_node_heartbeats()
            time.sleep(10)

    def file_health_periodic(self):
        while True:
            self.check_file_health()
            time.sleep(60)

    # Check heartbeats for each node
    def check_node_heartbeats(self):
        nodes = self.db.collection(u'nodes').stream()
        for node in nodes:
            protocol = node.get('protocol')
            hostname = node.get('hostname')
            port = node.get('port')
            try:
                url = protocol + "://" + hostname + ":" + str(port) + "/heartbeat"
                response = requests.get(url).text
                if response == "ALIVE":
                    self.db.collection("nodes").document(node.id).set({
                        "last_heartbeat_time": get_time()
                    }, merge=True)
            except Exception as e:
                pass

    def select_x_randomly(self, arr: list, amount: int):
        result = []
        for _ in range(amount):
            if len(arr) == 0:
                continue
            item = random.choice(arr)
            result.append(item)
            arr.remove(item)

        return result

    # Make sure that each file is on at least >= 60% of nodes
    # Otherwise, start node re-distribution
    def check_file_health(self):
        nodes = self.db.collection(u'nodes').stream()

        all_nodes = {}
        alive_nodes = {}  # Mapping of node id to node
        dead_nodes = {}  # Mapping of node id to node
        # Mapping of str<file id> to list of node ids
        file_to_alive_nodes = defaultdict(list)

        for node in nodes:
            node_id = node.id
            # Add to appropriate node
            is_alive = get_elapsed(node.get("last_heartbeat_time"))
            all_nodes[node_id] = node
            (alive_nodes if is_alive else dead_nodes)[node_id] = node

            if is_alive:
                # Track files
                node_file_refs = node.get("files_hosted")
                for file_ref in node_file_refs:
                    file_id = file_ref.id
                    node_list = file_to_alive_nodes[file_id]
                    node_list.append(node_id)

        number_of_nodes = len(all_nodes)
        number_of_alive_nodes = len(alive_nodes)
        files = self.db.collection(u'files').stream()
        for file in files:
            file_id = file.id
            if file_id not in file_to_alive_nodes:
                # File is completely lost
                continue
            alive_nodes_with_file = file_to_alive_nodes[file_id]
            percent_with_file = (len(alive_nodes_with_file) / number_of_nodes)
            if percent_with_file < FILE_REDUNDANCY_THRESHOLD:
                print(f"File with id {file_id} is only on " + str(percent_with_file * 100) + "% of nodes, so replicating..")
                # Do replication
                needed_total_alive_nodes_with_file = math.ceil(number_of_alive_nodes * FILE_REDUNDANCY_THRESHOLD)
                needed_additional_alive_nodes = abs(needed_total_alive_nodes_with_file - len(alive_nodes_with_file))
                alive_nodes_without_file = []
                for alive_node in alive_nodes.keys():
                    if alive_node not in alive_nodes_with_file:
                        alive_nodes_without_file.append(alive_node)

                nodes_to_replicate_to = self.select_x_randomly(alive_nodes_without_file, needed_additional_alive_nodes)
                for to_node_id in nodes_to_replicate_to:
                    from_node_id = random.choice(alive_nodes_with_file)
                    from_node = all_nodes[from_node_id]
                    to_node = all_nodes[to_node_id]
                    print(f"Replicating file from {from_node_id} to {to_node_id}")
                    url = from_node.get("protocol") + "://" + from_node.get("hostname") + ":" + \
                          str(from_node.get("port")) + "/send_file_to_node/" + file_id
                    requests.post(url, data={
                        "protocol": to_node.get("protocol"),
                        "hostname": to_node.get("hostname"),
                        "port": to_node.get("port")
                    })

    @flask_app.route("/new_file", methods=['POST'])
    def new_file():
        global cnc_node
        real_name = request.form.get("real_name")
        file_size = request.form.get("size_bits")
        file_hash = request.form.get("hash")

        doc_ref = cnc_node.db.collection(u'files').add({
            "real_name": real_name,
            "size_bits": int(file_size),
            "hash": file_hash
        })

        # TODO : Improve algorithm
        # Now just going to upload to all alive nodes
        upload_to_nodes = []
        nodes = cnc_node.db.collection(u'nodes').stream()
        for node in nodes:
            # if node was alive within last minute
            if get_elapsed(node.get("last_heartbeat_time")) <= 60:
                upload_to_nodes.append({
                    "protocol": node.get("protocol"),
                    "hostname": node.get("hostname"),
                    "port": node.get("port")
                })

        file_id = doc_ref[1].id

        return jsonify({
            "file_id": file_id,
            "upload_to_nodes": upload_to_nodes
        })

    @flask_app.route("/delete_file/<file_id>", methods=['POST'])
    def delete_file(file_id):
        nodes = cnc_node.db.collection(u'nodes').stream()

        # Delete from each node which has the file
        for node in nodes:
            node_file_refs = node.get("files_hosted")
            for file_ref in node_file_refs:
                if file_ref.id == file_id:
                    url = node.get("protocol") + "://" + node.get("hostname") + ":" \
                          + str(node.get("port")) + "/delete_node_file/" + file_id
                    requests.post(url)
                    break

        # Delete from db
        cnc_node.db.collection("files").document(file_id).delete()

        return jsonify({
            "message": "Success"
        })

    @flask_app.route("/file_info/<file>")
    def file_info(file):
        doc_ref = cnc_node.db.collection("files").document(file)
        doc = doc_ref.get()
        if not doc.exists:
            abort(500)
            return

        return jsonify({
            "file_id": file,
            "real_name": doc.get("real_name"),
            "size_bits": doc.get("size_bits"),
            "hash": doc.get("hash")
        })

    @flask_app.route("/notify_received_file/<node_id>", methods=['POST'])
    def notify_file_received(node_id):
        global cnc_node
        # Get node
        node_ref = cnc_node.db.collection("nodes").document(node_id)
        node_snapshot = node_ref.get()
        if not node_snapshot.exists:
            abort(500)
            return

        file_id = request.form.get("file_id")
        current_file_refs = node_snapshot.get("files_hosted")
        current_file_ids = [file_ref.id for file_ref in current_file_refs]
        # Error if we already know this node has this file
        if file_id in current_file_ids:
            abort(500)
            return

        # Otherwise add new reference to files_hosted of node in db
        file_ref = cnc_node.db.collection("files").document(file_id)

        node_ref.update({
            "files_hosted": ArrayUnion([file_ref])
        })

        return jsonify({
            "message": "Success"
        })

    @flask_app.route('/get_file/<file_id>', methods=['GET'])
    def get_file(file_id):
        file_ref = cnc_node.db.collection("files").document(file_id)
        file_snapshot = file_ref.get()
        if not file_snapshot.exists:
            abort(500)
            return jsonify({
                "error": "File with id not found."
            })

        if 'latitude' in request.form and 'longitude' in request.form:
            latitude = request.form.get("latitude")
            longitude = request.form.get("longitude")
        else:
            ip_address = request.remote_addr
            if ip_address in ip_address_to_location_map:
                latitude = ip_address_to_location_map[ip_address]["latitude"]
                longitude = ip_address_to_location_map[ip_address]["longitude"]
            else:
                # Find latitude longitude
                details = cnc_node.ip_info.getDetails(ip_address)
                details_latitude = details.latitude
                details_longitude = details.longitude
                if not details_latitude:
                    details_latitude = 0
                if not details_longitude:
                    details_longitude = 0
                latitude = float(details_latitude)
                longitude = float(details_longitude)
                ip_address_to_location_map[ip_address] = {
                    "latitude": latitude,
                    "longitude": longitude
                }

        # Look for nodes with the file and FIND the closest node geographically
        nodes = cnc_node.db.collection(u'nodes').stream()
        smallest_distance = float('inf')
        best_node = None
        for node in nodes:
            node_file_refs = node.get("files_hosted")
            node_has_file = False

            for file_ref in node_file_refs:
                if file_ref.id == file_id:
                    node_has_file = True
                    break
            if not node_has_file:
                continue
            location = node.get("location")
            node_latitude = location.latitude
            node_longitude = location.longitude
            distance_to_node = haversine(node_latitude, node_longitude, latitude, longitude)
            if distance_to_node < smallest_distance:
                smallest_distance = distance_to_node
                best_node = node

        if best_node:
            file_url = best_node.get("protocol") + "://" + best_node.get("hostname") + ":" \
                       + str(best_node.get("port")) + "/get_node_file/" + file_id
            return redirect(file_url, 302)
        else:
            abort(500)
            return jsonify({
                "error": "Found no nodes containing the file."
            })


end_node = None  # type: Optional[CDNEndNode]
cnc_url = "http://localhost:9981/"


# End node server (serves files)
class CDNEndNode(CDNProgram):
    def __init__(self):
        global end_node
        end_node = self
        self.port = None
        self.node_id = None

    def start(self):
        if len(sys.argv) < 4:
            print("Please specify port and node token as second and third argument")
            exit(1)
        self.port = int(sys.argv[2])
        self.node_id = sys.argv[3]

        if not os.path.exists("node_files"):
            os.mkdir("node_files")

        print("End node started.")
        flask_app.run(host='0.0.0.0', port=self.port)

    @flask_app.route("/heartbeat")
    def heartbeat():
        return "ALIVE"

    @flask_app.route("/accept_new_file/<file_id>", methods=['POST'])
    def accept_new_file(file_id: str):
        file_id = os.path.basename(file_id)
        real_name, size_bits, file_hash = get_file_info(file_id)
        if not real_name:
            return

        # save the file locally
        local_directory = "node_files/" + file_id + "/"
        local_file_path = local_directory + real_name
        if os.path.exists(local_file_path):
            print('File already exists')
            abort(500)
            return

        if not os.path.exists(local_directory):
            os.mkdir(local_directory)

        f = request.files['file']
        bytes = f.read()
        uploaded_file_hash = hashlib.sha256(bytes).hexdigest()

        if uploaded_file_hash != file_hash:
            print('File hash is invalid, it is ' + uploaded_file_hash)
            abort(500)
            return jsonify({
                "error": "Invalid file contents, based on hash."
            })

        file = open(local_file_path, 'wb')
        file.write(bytes)
        file.close()

        # Tell the cnc server we host a new file
        requests.post(cnc_url + "/notify_received_file/" + end_node.node_id, {
            "file_id": file_id
        })

        return jsonify({
            "message": "Success"
        })

    @flask_app.route("/get_node_file/<file_id>")
    def get_node_file(file_id: str):
        file_id = os.path.basename(file_id)
        real_name, size_bits, file_hash = get_file_info(file_id)
        if not real_name:
            return

        local_file_path = "node_files/" + file_id + "/" + real_name
        if not os.path.exists(local_file_path):
            abort(500)
            return

        return send_file(local_file_path, as_attachment=True)

    @flask_app.route("/delete_node_file/<file_id>", methods=['POST'])
    def delete_node_file(file_id: str):
        file_id = os.path.basename(file_id)
        local_directory = "node_files/" + file_id + "/"
        if not os.path.exists(local_directory):
            abort(500)
            return

        shutil.rmtree(local_directory)

        return jsonify({
            "message": "Success"
        })

    @flask_app.route('/send_file_to_node/<file_id>', methods=['POST'])
    def send_file_to_node(file_id: str):
        file_id = os.path.basename(file_id)
        real_name, size_bits, file_hash = get_file_info(file_id)
        if not real_name:
            return

        local_file_path = "node_files/" + file_id + "/" + real_name
        if not os.path.exists(local_file_path):
            abort(500)
            return

        # To Node information
        protocol = request.form.get("protocol")
        hostname = request.form.get("hostname")
        port = request.form.get("port")

        url = protocol + "://" + hostname + ":" + str(port) + "/accept_new_file/" + file_id

        try:
            file = open(local_file_path, 'rb')
            up = {'file': (real_name, file)}
            response = requests.post(url, files=up)
            file.close()
            response.raise_for_status()
            return jsonify({
                "message": "Success"
            })
        except HTTPError:
            abort(500)
            return


def get_file_info(file_id):
    global cnc_url
    try:
        response = requests.get(cnc_url + "file_info/" + file_id)
        response.raise_for_status()
        json = response.json()
    except HTTPError:
        abort(500)
        return None, None, None

    return json["real_name"], json["size_bits"], json["hash"]


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Please provide client or server as the first argument for program type')
        exit(1)
    app_type = sys.argv[1]

    # Start the correct program
    if app_type == "server":
        CDNCNCNode().start()
    elif app_type == "client":
        CDNEndNode().start()
    else:
        print('Invalid program type')
