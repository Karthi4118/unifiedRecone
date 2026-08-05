import urllib.request
import json
import sys

BASE_URL = "http://localhost:8000"

def run_test(name, path, method="GET", data=None, expected_status=200):
    print(f"Running test: {name}...", end=" ")
    url = f"{BASE_URL}{path}"
    encoded_data = json.dumps(data).encode('utf-8') if data else None
    headers = {'Content-Type': 'application/json'} if data else {}
    
    req = urllib.request.Request(url, data=encoded_data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            body = json.loads(resp.read().decode('utf-8'))
            if resp.status == expected_status:
                print("\033[92mPASSED\033[0m")
                return body
            else:
                print(f"\033[91mFAILED (Expected status {expected_status}, got {resp.status})\033[0m")
                sys.exit(1)
    except urllib.error.HTTPError as e:
        if e.code == expected_status:
            body = json.loads(e.read().decode('utf-8'))
            print("\033[92mPASSED\033[0m")
            return body
        else:
            print(f"\033[91mFAILED (HTTP Status {e.code}, expected {expected_status})\033[0m")
            sys.exit(1)
    except Exception as e:
        print(f"\033[91mFAILED ({str(e)})\033[0m")
        sys.exit(1)

def main():
    print("==================================================")
    print(" SentinelRecon Authentication & Roles API Tests  ")
    print("==================================================")
    
    # 1. Test POST /api/login - Standard User
    user_login = run_test(
        "POST /api/login (Standard User)",
        "/api/login",
        method="POST",
        data={"email": "user@gmail.com", "password": "userpass"}
    )
    assert user_login["success"] is True, "Failed login success check"
    assert user_login["role"] == "user", "Mismatched role in user auth response"

    # 2. Test POST /api/login - Admin User
    admin_login = run_test(
        "POST /api/login (Admin User)",
        "/api/login",
        method="POST",
        data={"email": "admin@gmail.com", "password": "adminpass"}
    )
    assert admin_login["success"] is True, "Failed login success check"
    assert admin_login["role"] == "admin", "Mismatched role in admin auth response"

    # 3. Test POST /api/login - Bad Credentials (401)
    bad_login = run_test(
        "POST /api/login (Bad credentials -> 401)",
        "/api/login",
        method="POST",
        data={"email": "admin@gmail.com", "password": "badpassword"},
        expected_status=401
    )
    assert bad_login["success"] is False, "Bad login should return success: False"

    # 4. Test POST /api/forgot-password - Update User Password
    run_test(
        "POST /api/forgot-password (Successful Update)",
        "/api/forgot-password",
        method="POST",
        data={"email": "user@gmail.com", "password": "newuserpass"}
    )

    # 5. Test login with newly updated password
    new_login = run_test(
        "POST /api/login (With newly updated password)",
        "/api/login",
        method="POST",
        data={"email": "user@gmail.com", "password": "newuserpass"}
    )
    assert new_login["success"] is True, "Should successfully authenticate with updated password"

    # Reset password back to original for subsequent tests
    run_test(
        "POST /api/forgot-password (Restore original password)",
        "/api/forgot-password",
        method="POST",
        data={"email": "user@gmail.com", "password": "userpass"}
    )

    # 6. Test GET /api/slides
    slides = run_test("GET /api/slides", "/api/slides")
    assert len(slides) > 0, "No slides returned"

    # 7. Test GET /api/history - Unauthorized (403 for non-admin)
    run_test(
        "GET /api/history (Unauthorized Role -> 403)",
        "/api/history?role=user",
        expected_status=403
    )

    # 8. Test GET /api/history - Authorized (200 for admin)
    run_test(
        "GET /api/history (Authorized Admin -> 200)",
        "/api/history?role=admin"
    )

    # 9. Test GET /api/admin/users - Unauthorized (403 for non-admin)
    run_test(
        "GET /api/admin/users (Unauthorized user directory query -> 403)",
        "/api/admin/users?role=user",
        expected_status=403
    )

    # 10. Test GET /api/admin/users - Authorized (200 for admin)
    users_data = run_test(
        "GET /api/admin/users (Authorized Admin query -> 200)",
        "/api/admin/users?role=admin"
    )
    assert users_data["total"] >= 2, "Should return at least 2 default registered users"

    print("==================================================")
    print(" \033[92mALL TESTS COMPLETED SUCCESSFULLY (STATE MATCHED)\033[0m ")
    print("==================================================")

if __name__ == '__main__':
    main()
