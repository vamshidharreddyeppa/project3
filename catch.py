import argparse
import csv
import math
from datetime import datetime, timedelta


required = ["ts", "user", "event", "result", "role", "country", "city", "lat", "lon", "src_ip"]


def convertTime(val):
    dt = datetime.fromisoformat(val)
    return dt


def loadData(filename):
    all_events = []

    f = open(filename, newline="")
    reader = csv.DictReader(f)

    lineNum = 2
    for row in reader:
        try:
            for field in required:
                if field not in row or row[field] == "":
                    raise ValueError("missing field " + field)

            e = {}
            e["ts"] = convertTime(row["ts"])
            e["ts_raw"] = row["ts"]
            e["user"] = row["user"]
            e["event"] = row["event"]
            e["result"] = row["result"]
            e["role"] = row["role"]
            e["country"] = row["country"]
            e["city"] = row["city"]
            e["lat"] = float(row["lat"])
            e["lon"] = float(row["lon"])
            e["src_ip"] = row["src_ip"]
            e["line_no"] = lineNum

            all_events.append(e)

        except Exception as err:
            print("skipping bad line", lineNum, ":", err)

        lineNum += 1

    f.close()
    all_events.sort(key=lambda x: x["ts"])
    return all_events


def calc_distance(lat1, lon1, lat2, lon2):
    R = 6371.0
    lat1 = math.radians(lat1)
    lon1 = math.radians(lon1)
    lat2 = math.radians(lat2)
    lon2 = math.radians(lon2)
    d_lat = lat2 - lat1
    d_lon = lon2 - lon1

    a = math.sin(d_lat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(d_lon / 2) ** 2
    dist = 2 * R * math.asin(math.sqrt(a))
    return dist


def makeAlert(time, username, atype, msg):
    alert = {
        "ts": time,
        "user": username,
        "attack_type": atype,
        "reason": msg,
    }
    return alert


def checkImpossibleTravel(events, max_speed=900.0):
    alerts = []
    last_seen = {}

    logins = []
    for e in events:
        if e["event"] == "login" and e["result"] == "success":
            logins.append(e)

    for event in logins:
        user = event["user"]

        if user in last_seen:
            prev = last_seen[user]
            diff = event["ts"] - prev["ts"]
            hours = diff.total_seconds() / 3600

            if hours > 0:
                km = calc_distance(prev["lat"], prev["lon"], event["lat"], event["lon"])
                speed = km / hours
                if speed > max_speed:
                    mins = hours * 60
                    msg = (
                        prev["city"]
                        + " to "
                        + event["city"]
                        + " in "
                        + str(round(mins))
                        + " minutes, implied speed "
                        + str(round(speed))
                        + " km/h"
                    )
                    a = makeAlert(event["ts_raw"], user, "impossible_travel", msg)
                    alerts.append(a)

        last_seen[user] = event

    return alerts


def checkOffHoursAdmin(events, start_hour=8, end_hour=18):
    alerts = []

    for e in events:
        if e["role"] == "admin" and e["result"] == "success":
            hour = e["ts"].hour

            is_service = e["role"] == "service" or e["user"].startswith("svc_")

            if not is_service:
                if hour < start_hour or hour >= end_hour:
                    msg = "admin activity outside business hours at " + e["ts_raw"]
                    a = makeAlert(e["ts_raw"], e["user"], "off_hours_admin", msg)
                    alerts.append(a)

    return alerts


def checkBruteForce(events, window_minutes=5, failure_limit=5):
    alerts = []
    failures_by_user = {}

    for e in events:
        if e["event"] == "login" and e["result"] == "failure":
            user = e["user"]
            if user not in failures_by_user:
                failures_by_user[user] = []
            failures_by_user[user].append(e)

    for user in failures_by_user:
        failures = failures_by_user[user]
        failures.sort(key=lambda x: x["ts"])

        for i in range(len(failures)):
            start_time = failures[i]["ts"]
            end_time = start_time + timedelta(minutes=window_minutes)
            count = 0

            for e in failures:
                if start_time <= e["ts"] <= end_time:
                    count += 1

            if count >= failure_limit:
                msg = str(count) + " failed logins for " + user + " within " + str(window_minutes) + " minutes"
                a = makeAlert(failures[i]["ts_raw"], user, "brute_force", msg)
                alerts.append(a)
                break

    return alerts


def checkPasswordSpray(events, window_minutes=10, user_limit=5):
    alerts = []
    failures_by_ip = {}

    for e in events:
        if e["event"] == "login" and e["result"] == "failure":
            ip = e["src_ip"]
            if ip not in failures_by_ip:
                failures_by_ip[ip] = []
            failures_by_ip[ip].append(e)

    for ip in failures_by_ip:
        failures = failures_by_ip[ip]
        failures.sort(key=lambda x: x["ts"])

        for i in range(len(failures)):
            start_time = failures[i]["ts"]
            end_time = start_time + timedelta(minutes=window_minutes)
            users = []
            window_events = []

            for e in failures:
                if start_time <= e["ts"] <= end_time:
                    window_events.append(e)
                    if e["user"] not in users:
                        users.append(e["user"])

            if len(users) >= user_limit:
                used = []
                for e in window_events:
                    if e["user"] not in used:
                        msg = ip + " failed logins across " + str(len(users)) + " users within " + str(window_minutes) + " minutes"
                        a = makeAlert(e["ts_raw"], e["user"], "password_spray", msg)
                        alerts.append(a)
                        used.append(e["user"])
                break

    return alerts


def loadTruth(filename):
    truth = set()

    f = open(filename, newline="")
    reader = csv.DictReader(f)

    for row in reader:
        if row.get("label") == "malicious":
            key = (row["ts"], row["user"], row["attack_type"])
            truth.add(key)

    f.close()
    return truth


def alertKey(alert):
    return (alert["ts"], alert["user"], alert["attack_type"])


def scoreAlerts(alerts, truth):
    predicted = set()

    for a in alerts:
        predicted.add(alertKey(a))

    true_pos = predicted & truth
    false_pos = predicted - truth
    false_neg = truth - predicted

    if len(predicted) > 0:
        precision = len(true_pos) / len(predicted)
    else:
        precision = 0

    if len(truth) > 0:
        recall = len(true_pos) / len(truth)
    else:
        recall = 0

    print()
    print("SCORE")
    print("true positives:", len(true_pos))
    print("false positives:", len(false_pos))
    print("false negatives:", len(false_neg))
    print("precision:", format(precision, ".2f"))
    print("recall:", format(recall, ".2f"))

    print()
    print("FALSE POSITIVES")
    if len(false_pos) == 0:
        print("none")
    else:
        for item in sorted(false_pos):
            print(item)

    print()
    print("FALSE NEGATIVES")
    if len(false_neg) == 0:
        print("none")
    else:
        for item in sorted(false_neg):
            print(item)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("logfile")
    parser.add_argument("--truth")
    parser.add_argument("--threshold-kmh", type=float, default=900.0)
    args = parser.parse_args()

    events = loadData(args.logfile)

    alerts = []
    alerts.extend(checkImpossibleTravel(events, args.threshold_kmh))
    alerts.extend(checkOffHoursAdmin(events))
    alerts.extend(checkBruteForce(events))
    alerts.extend(checkPasswordSpray(events))

    alerts.sort(key=lambda x: (x["ts"], x["user"], x["attack_type"]))

    print("ALERTS")
    for a in alerts:
        print(a["ts"] + "," + a["user"] + "," + a["attack_type"] + "," + a["reason"])

    if args.truth:
        truth = loadTruth(args.truth)
        scoreAlerts(alerts, truth)


if __name__ == "__main__":
    main()
