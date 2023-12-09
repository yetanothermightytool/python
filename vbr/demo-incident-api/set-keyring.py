import keyring

# Use the same service name as in the main script
service  = "IncidentAPI"
username = "Administrator"
password = "<YourS3curePasswordH3rE>"

keyring.set_password(service, username, password)
