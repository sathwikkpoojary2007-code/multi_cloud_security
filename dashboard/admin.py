"""Command line account provisioning. There is intentionally no public signup."""

import argparse
from getpass import getpass

from dashboard.auth import create_user, init_db, user_count


def main(argv=None):
    parser = argparse.ArgumentParser(description="Provision a MultiCloudSecurity dashboard account.")
    parser.add_argument("command", choices=("create-admin", "create-user"))
    parser.add_argument("--username")
    parser.add_argument("--role", choices=("admin", "operator", "viewer"), default="viewer")
    args = parser.parse_args(argv)

    init_db()
    if args.command == "create-admin" and user_count():
        parser.error("Accounts already exist. Use create-user to add another account.")
    username = args.username or input("Username: ").strip()
    password = getpass("Password (12+ characters): ")
    confirm = getpass("Confirm password: ")
    if password != confirm:
        parser.error("Passwords do not match.")
    role = "admin" if args.command == "create-admin" else args.role
    try:
        create_user(username, password, role)
    except ValueError as error:
        parser.error(str(error))
    print(f"Created {role} account '{username}'.")


if __name__ == "__main__":
    main()
