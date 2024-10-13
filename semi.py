from selenium import webdriver
import requests
from z3 import *
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.common.keys import Keys  # Import Keys
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import UnexpectedAlertPresentException, NoAlertPresentException, TimeoutException
import logging
import time


# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 1. Define the Secure Model
class SecureModel:
    def __init__(self):
        self.users = ["admin", "user"]
        self.roles = {
            "admin": ["view_all_profiles", "edit_profiles"],
            "user": ["view_own_profile"]  # Limited permissions for non-admin users
        }
        self.profiles = {
            "user1": "Profile data for user1",  # Admin should access
            "user2": "Profile data for user2"   # User should access
        }
        logging.info("SecureModel initialized with roles: %s", self.roles)


    def is_authorized(self, user, action):
        logging.debug("Checking authorization for user: %s, action: %s", user, action)
        return action in self.roles.get(user, [])

    def update_permissions(self, user, action):
        logging.warning(f"Unauthorized access attempt detected by {user} for action: {action}")
        if user == "user" and action == "view_all_profiles":
            # Example of changing permissions - could implement more sophisticated logic
            self.roles["user"].append(action)  # Simulating changing role (for demonstration)
            logging.info("Permissions updated for user: %s, action: %s", user, action)


# 2. Mutation Operators
def mutate_model_for_vulnerability(model, action_to_remove):
    logging.info("Mutating model to remove action: %s", action_to_remove)

    def compromised_is_authorized(user, action):
        logging.debug("Action %s removed for user: %s", action_to_remove, user)
        if action == action_to_remove:
            return True  # Simulating a vulnerability (unauthorized access)
        return action in model.roles.get(user, [])
    
    model.is_authorized = compromised_is_authorized
    logging.info("Model mutation complete. New authorization logic applied.")

    return model

# 3. Attack Trace Generation using Z3
def find_attack_trace(model):
    user = String('user')
    action = String('action')
    s = Solver()
    s.add(user == "user", action == "view_all_profiles")
    s.add(Not(model.is_authorized(user, action)))
    
    if s.check() == sat:
        logging.info("Attack trace found for user: %s, action: %s", user, action)
        return s.model()
    else:
        logging.info("No attack trace found for user: %s, action: %s", user, action)
        return None

# New Function for SQL Injection Simulation
def simulate_sql_injection(model):
    user = String('user')
    action = String('action')
    s = Solver()
    # Simulate SQL Injection attempt
    s.add(user == "user", action == "view_all_profiles OR 1=1--")  # A typical SQL Injection payload
    s.add(Not(model.is_authorized(user, action)))
    
    if s.check() == sat:
        logging.info("SQL Injection attack trace found.")
        return s.model()
    else:
        logging.info("No SQL Injection attack trace found.")
        return None

# 4. WAAL Actions and Test Execution
class WAAL:
    def __init__(self, driver):
        self.driver = driver

    def login(self, email, password):
        self.driver.get("http://localhost:3000/#/login")
        logging.info("Navigated to login page.")

        # Wait for the close dialog button and click it
        try:
            close_dialog_button = WebDriverWait(self.driver, 10).until(
                EC.element_to_be_clickable((By.CSS_SELECTOR, ".mat-focus-indicator.close-dialog"))
            )
            close_dialog_button.click()
            logging.info("Clicked the close dialog button.")
        except Exception as e:
            logging.warning("Could not find the close dialog button: %s", str(e))

        # Wait for the email field to be present
        email_field = WebDriverWait(self.driver, 10).until(
            EC.presence_of_element_located((By.ID, "email"))
        )
        email_field.send_keys(email)

        # Wait for the password field to be present
        password_field = WebDriverWait(self.driver, 10).until(
            EC.presence_of_element_located((By.ID, "password"))
        )
        password_field.send_keys(password)

        # Wait for the login button to be clickable
        login_button = WebDriverWait(self.driver, 10).until(
            EC.element_to_be_clickable((By.CSS_SELECTOR, "button[type='submit']"))
        )

        # Scroll the login button into view and click it
        self.driver.execute_script("arguments[0].scrollIntoView();", login_button)
        self.driver.execute_script("arguments[0].click();", login_button)
        logging.info("Clicked the login button.")

    def view_profile(self, profile_id):
        # Navigate to the profile page
        self.driver.get(f"http://localhost:3000/#/profile/{profile_id}")
        logging.info("Navigated to profile page: %s", profile_id)
        return self.driver.page_source

    def test_xss_vulnerability(self):
        # Attempt to inject a script into a profile name field or comment box
        xss_payload = "<iframe src='javascript:alert(`XSS attack`)'>"
        
        # Access a page where the injection could occur
        self.driver.get("http://localhost:3000/#/profile/user2")  # Example page
        logging.info("Accessed profile page for XSS testing.")
        
        try:
            search_icon = WebDriverWait(self.driver, 10).until(
                EC.element_to_be_clickable((By.ID, "searchQuery"))
            )

            search_icon.click()
            logging.info("Clicked the search icon.")
            
        except Exception as e:
            logging.warning("Could not find search icon: %s", str(e))
        
        time.sleep(1)
        try:
            # Locate the input field in search bar
            search_bar = WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.ID, "mat-input-0"))
            )
            search_bar.send_keys(xss_payload)
            
            time.sleep(1)
            search_bar.send_keys(Keys.RETURN)
            
            time.sleep(1)

        # Handle any potential alert triggered by XSS
            try:
                alert = WebDriverWait(self.driver, 10).until(EC.alert_is_present())
                alert_text = alert.text
                logging.info(f"Alert detected with text: {alert_text}")
                alert.accept()
                logging.info("Alert accepted.")
                return True
            except TimeoutException:
                logging.info("No alert detected.")
        except TimeoutException:
            logging.warning("Could not find the comment field or submit button.")

        logging.info("No XSS vulnerability detected.")
        return False

# 5. Main Execution Flow
def execute_attack(model, attack_trace):
    driver = webdriver.Chrome()  # Ensure ChromeDriver is installed
    waal = WAAL(driver)

    # Simulate login with a non-admin user
    waal.login("tina@yopmail.com", "password")  # Non-admin user logs in

    # Use requests for HTTP interaction
    session = requests.Session()
    
    # Attempting to access another user's profile (user1 should not be accessible to non-admin)
    profile_to_access = "user1"
    response = session.get(f"http://localhost:3000/#/profile/{profile_to_access}")

    # Validate the response
    if "Unauthorized" in response.text:
        logging.info(f"Test passed: No unauthorized access to {profile_to_access}'s profile.")
    else:
        logging.error(f"Security flaw detected: Unauthorized access allowed to {profile_to_access}'s profile!")
        # Update model if unauthorized access is detected
        model.update_permissions("user", "view_all_profiles")

        # Log the test case generated for unauthorized access
        test_case = {
            "test_case_id": 1,
            "description": "Unauthorized access attempt",
            "expected_result": "Access Denied",
            "actual_result": "Access Granted",
            "user": "tina@yopmail.com",
            "action": "view_all_profiles",
            "target_profile": profile_to_access
        }
        logging.info(f"Test Case Generated: {test_case}")

    # Simulate SQL Injection to see if the application handles it
    sql_injection_trace = simulate_sql_injection(model)
    if sql_injection_trace:
        logging.info("SQL Injection trace generated. Test case ready.")
        # Log the test case for SQL Injection
        sql_injection_test_case = {
            "test_case_id": 2,
            "description": "SQL Injection Attempt",
            "payload": "view_all_profiles OR 1=1--",
            "expected_result": "Error or Unauthorized Access",
            "actual_result": "Check server response",
            "user": "user",
            "action": "SQL Injection"
        }
        logging.info(f"SQL Injection Test Case Generated: {sql_injection_test_case}")

    # Test for XSS vulnerability
    if waal.test_xss_vulnerability():
        xss_test_case = {
            "test_case_id": 3,
            "description": "XSS Attack Attempt",
            "payload": "<script>alert('XSS Vulnerability!');</script>",
            "expected_result": "Script should not execute",
            "actual_result": "Check for alert or presence of payload in page",
            "user": "tina@yopmail.com",
            "action": "XSS Attack"
        }
        logging.info(f"XSS Test Case Generated: {xss_test_case}")

    driver.quit()

# Running the implementation
if __name__ == "__main__":
    secure_model = SecureModel()
    compromised_model = mutate_model_for_vulnerability(secure_model, "view_all_profiles")
    trace = find_attack_trace(compromised_model)
    if trace:
        execute_attack(compromised_model, trace)
    else:
        logging.warning("No attack trace found.")
