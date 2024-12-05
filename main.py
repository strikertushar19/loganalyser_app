import re
import csv
from collections import defaultdict

LOG_FILE = "sample.log"
OUTPUT_FILE = "log_analysis_results.csv"


# regex patters to get meaningful data from sample.log file to process the information
IP_REGEX = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
ENDPOINT_REGEX = r'\"[A-Z]+\s([^\s]+)\sHTTP'
STATUS_CODE_REGEX = r"\" (\d{3}) "


# helper class to set threshold value
class LogConfig:
    def __init__(self, failed_login_threshold=10):
        self.failed_login_threshold = failed_login_threshold
    
    #function to set threshold value apart from default 10 for suspicous activity tracker
    def set_threshold(self, threshold):
        self.failed_login_threshold = threshold


# log analysis class with required functionalities
class LogAnalyzer:
    def __init__(self, log_file, config):
        self.log_file = log_file
        self.config = config
        self.log_lines = self.read_log_file()

    def read_log_file(self):
        with open(self.log_file, "r") as file:
            return file.readlines()

    # function to count requests per ip address
    def count_requests_per_ip(self):
        ip_counts = defaultdict(int)
        for line in self.log_lines:
            ip_match = re.search(IP_REGEX, line)
            if ip_match:
                ip_counts[ip_match.group()] += 1
        return sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)

        # most accessed point funtion
    def most_accessed_endpoint(self):
        endpoint_counts = defaultdict(int)
        for line in self.log_lines:
            endpoint_match = re.search(ENDPOINT_REGEX, line)
            if endpoint_match:
                endpoint_counts[endpoint_match.group(1)] += 1
        most_accessed = max(endpoint_counts.items(), key=lambda x: x[1])
        return most_accessed
    

    # suspicious activity detection function
    def detect_suspicious_activity(self):
        failed_logins = defaultdict(int)
        for line in self.log_lines:
            status_match = re.search(STATUS_CODE_REGEX, line)
            ip_match = re.search(IP_REGEX, line)
            if status_match and ip_match and status_match.group(1) == "401":
                failed_logins[ip_match.group()] += 1
        return {ip: count for ip, count in failed_logins.items() if count > self.config.failed_login_threshold}

    def save_results_to_csv(self, ip_requests, most_accessed, suspicious_activities):
        with open(OUTPUT_FILE, "w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["Requests per IP"])
            writer.writerow(["IP Address", "Request Count"])
            writer.writerows(ip_requests)
            writer.writerow([])

            writer.writerow(["Most Accessed Endpoint"])
            writer.writerow(["Endpoint", "Access Count"])
            writer.writerow([most_accessed[0], most_accessed[1]])
            writer.writerow([])

            writer.writerow(["Suspicious Activity"])
            writer.writerow(["IP Address", "Failed Login Count"])
            for ip, count in suspicious_activities.items():
                writer.writerow([ip, count])

class LogAnalysisApp:
    def __init__(self):
        self.config = LogConfig()
        self.analyzer = LogAnalyzer(LOG_FILE, self.config)

    def run(self):
        try:
            threshold = int(input("Enter the threshold value for failed login attempts: "))
            self.config.set_threshold(threshold)
        except ValueError:
            print("Invalid threshold value. Using default value of 10.")

        self.show_menu()

    def show_menu(self):
        while True:
            print("\nSelect an option to view the analysis result:")
            print("1. View Requests per IP")
            print("2. View Most Accessed Endpoint")
            print("3. View Suspicious Activity")
            print("4. View All Results ")
            print("5. Exit")

            choice = input("Enter the number of your choice: ")

            if choice == "1":
                self.view_requests_per_ip()
            elif choice == "2":
                self.view_most_accessed_endpoint()
            elif choice == "3":
                self.view_suspicious_activity()
            elif choice == "4":
                self.view_all_results()
                break
            elif choice == "5":
                print("Exiting the program.")
                break
            else:
                print("Invalid choice. Please try again.")

        # Display  requests per ip address only
    def view_requests_per_ip(self):
        ip_requests = self.analyzer.count_requests_per_ip()
        print("Requests per IP:")
        print("IP Address".ljust(20) + "Request Count")
        for ip, count in ip_requests:
            print(ip.ljust(20) + str(count))

        #  Display most accessed point only
    def view_most_accessed_endpoint(self):
        most_accessed = self.analyzer.most_accessed_endpoint()
        print("\nMost Frequently Accessed Endpoint:")
        print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

        # Display suspicous activity tracker only
    def view_suspicious_activity(self):
        suspicious_activities = self.analyzer.detect_suspicious_activity()
        print("\nSuspicious Activity Detected:")
        print("IP Address".ljust(20) + "Failed Login Attempts")
        for ip, count in suspicious_activities.items():
            print(ip.ljust(20) + str(count))

        # Display all results
    def view_all_results(self):
        ip_requests = self.analyzer.count_requests_per_ip()
        most_accessed = self.analyzer.most_accessed_endpoint()
        suspicious_activities = self.analyzer.detect_suspicious_activity()


        print("\nRequests per IP:")
        print("IP Address".ljust(20) + "Request Count")
        for ip, count in ip_requests:
            print(ip.ljust(20) + str(count))

        print("\nMost Frequently Accessed Endpoint:")
        print("\nEndpoint \t\t\t Accessed ")

        print(f"{most_accessed[0]} \t\t\t\t  {most_accessed[1]} times")

        print("\nSuspicious Activity Detected:")
        print("IP Address".ljust(20) + "Failed Login Attempts")
        for ip, count in suspicious_activities.items():
            print(ip.ljust(20) + str(count))

        self.analyzer.save_results_to_csv(ip_requests, most_accessed, suspicious_activities)
        print(f"\nResults saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    app = LogAnalysisApp()
    app.run()
