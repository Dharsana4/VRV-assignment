import csv
from collections import defaultdict
FAILED_LOGIN_THRESHOLD = 10
def parse_log_file(file_path):
    with open(file_path, 'r') as file:
        logs = file.readlines()
    return logs

def count_requests_per_ip(logs):
    ip_request_count = defaultdict(int)
    for log in logs:
        ip = log.split()[0]
        ip_request_count[ip] += 1
    return sorted(ip_request_count.items(), key=lambda x: x[1], reverse=True)

def find_most_accessed_endpoint(logs):
    endpoint_count = defaultdict(int)
    for log in logs:
        parts = log.split('"')
        if len(parts) > 1:
            endpoint = parts[1].split()[1]
            endpoint_count[endpoint] += 1
    return max(endpoint_count.items(), key=lambda x: x[1])

def detect_suspicious_activity(logs):
    failed_login_count = defaultdict(int)
    for log in logs:
        if '401' in log or "Invalid credentials" in log:
            ip = log.split()[0]
            failed_login_count[ip] += 1
    return {ip: count for ip, count in failed_login_count.items() if count > FAILED_LOGIN_THRESHOLD}

def save_to_csv(ip_counts, most_accessed, suspicious_activity):
    with open('log_analysis_results.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Requests per IP'])
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_counts:
            writer.writerow([ip, count])
        
        writer.writerow([])
        writer.writerow(['Most Accessed Endpoint'])
        writer.writerow(['Endpoint', 'Access Count'])
        writer.writerow([most_accessed[0], most_accessed[1]])
        
        writer.writerow([])

        writer.writerow(['Suspicious Activity'])
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])

def main():
    logs = parse_log_file(r'C:\Users\HP\Documents\Placements\VRV\sample_file.log')

    ip_counts = count_requests_per_ip(logs)
    most_accessed = find_most_accessed_endpoint(logs)
    suspicious_activity = detect_suspicious_activity(logs)

    print("IP Address           Request Count")
    for ip, count in ip_counts:
        print(f"{ip:20} {count}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")
    
    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in suspicious_activity.items():
        print(f"{ip:20} {count}")

    save_to_csv(ip_counts, most_accessed, suspicious_activity)

if __name__ == '__main__':
    main()
