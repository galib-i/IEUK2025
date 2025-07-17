from pathlib import Path
import pandas as pd
import re
import matplotlib.pyplot as plt

BASE_PATH = Path(__file__).parent
LOGS_FILE_PATH = BASE_PATH / "logs" / "sample-log.log"
REPORTS_DIR = BASE_PATH / "reports"

# Log pattern interpreted from the given sample-log
LOG_PATTERN = re.compile(
    r'(?P<ip>[\d\.]+) - (?P<country>\w{2}) - \[(?P<timestamp>.*?)\] "(?P<request>.*?)" (?P<status>\d{3}) (?P<size>\d+|-?) "(?P<referer>.*?)" "(?P<user_agent>.*?)" (?P<response_time>\d+)'
)


def parse_log_file(log_file_path):
    """Parses the log file and returns a DataFrame for analysis."""
    records = []
    try:
        with open(log_file_path, "r") as f:
            for line in f:
                match = LOG_PATTERN.match(line)

                if match:
                    records.append(match.groupdict())

    except FileNotFoundError:
        print(f"Error: {log_file_path} not found")
        return pd.DataFrame()

    if not records:
        print("Error: no log entry matches the regex pattern.")
        return pd.DataFrame()

    df = pd.DataFrame(records)
    df["timestamp"] = pd.to_datetime(df["timestamp"], format="%d/%m/%Y:%H:%M:%S")
    df["status"] = pd.to_numeric(df["status"])
    df["size"] = pd.to_numeric(df["size"].replace("-", "0"))
    df["response_time"] = pd.to_numeric(df["response_time"])

    return df


def generate_reports(log_df):
    REPORTS_DIR.mkdir(exist_ok=True)

    print("\nLog Analysis Report")
    print(f"Total Requests: {len(log_df)}")

    save_report(
        log_df["ip"].value_counts().head(10),
        "top_ips.txt",
        "Top 10 IP Addresses by Requests",
    )
    save_report(
        log_df["request"].value_counts().head(10),
        "top_urls.txt",
        "Top 10 Most Requested URLs",
    )
    save_report(
        log_df["user_agent"].value_counts().head(10),
        "top_user_agents.txt",
        "Top 10 User-Agents by Request Count",
    )

    save_suspicious_ips(log_df)
    generate_traffic_plot(log_df)


def save_report(data, filename, title):
    with open(REPORTS_DIR / filename, "w") as f:
        f.write(f"{title}:\n")
        f.write(data.to_string())


def save_suspicious_ips(log_df):
    request_counts = log_df["ip"].value_counts()
    suspicious_ips = request_counts[request_counts > 1000].index.tolist()

    with open(REPORTS_DIR / "suspicious_ips.txt", "w") as f:
        if suspicious_ips:
            f.write(f"Suspicious IPs with >1000 requests: {suspicious_ips}\n")
        else:
            f.write("No single IP made more than 1000 requests.\n")


def generate_traffic_plot(log_df):
    traffic_by_hour = log_df.set_index("timestamp").resample("h").size()
    traffic_by_hour.plot(title="Requests per Hour", figsize=(12, 6), grid=True)
    plt.xlabel("Time")
    plt.ylabel("Number of Requests")
    plt.tight_layout()
    plt.savefig(REPORTS_DIR / "hourly_traffic.png")

    plt.show()


def main():
    log_df = parse_log_file(LOGS_FILE_PATH)

    if not log_df.empty:
        generate_reports(log_df)
    else:
        print("Error: there is no valid log data to analyse.")


if __name__ == "__main__":
    main()
