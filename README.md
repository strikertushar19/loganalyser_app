# LOG ANALYSER APP

This app provides three main functionalities:

### 1. **Request Count by IP Address**
   - Analyzes the log file and calculates how many requests each IP address has made.
   - Displays the results in a neatly formatted table with "IP Address" and "Request Count".

### 2. **Most Accessed Endpoint**
   - This feature diplay the most accessed endpoint and how many times it is accessed as well .

### 3. **Suspicious Activity Dectection**
   - This feature allows to track which ip address is accessing endpoint with how many failed attempts or code 401 
   - It provides user option to provide threshold value or else use default 10 request per ip for failed attempts.

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