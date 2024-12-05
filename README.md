# LOG ANALYSER APP

This app provides three main functionalities:

### 1. **Request Count by IP Address**
   - Analyzes the log file and calculates how many requests each IP address has made.
   - Displays the results in a neatly formatted table with "IP Address" and "Request Count".

### 2. **Top N IPs**
   - Allows the user to specify a number (N) and returns the top N IP addresses that made the most requests.
   - Displays these top IPs in descending order of request count.

### 3. **Requests by Time Period**
   - Users can specify a time range (e.g., from `start_time` to `end_time`).
   - The app will then show the number of requests made by each IP within this time period.

## Installation

1. **Clone the repository**:
    ```bash
    git clone https://github.com/strikertushar19/loganalyser_app.git
    cd loganalyser_app
    ```

2. **Install dependencies**:
Make sure you have Python installed. You can install the required libraries using pip. Right now I am not using any
external libraries or modules apart from  built in regex patterns re module of python.



## Usage

### 1. **Running the App**
   After installation, you can run the app using the following command:

   ```bash
   python main.py
```
or

   ```bash
   python3 main.py
```