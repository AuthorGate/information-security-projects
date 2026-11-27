from .common import Reader, labels
from .policy_facts import inline_self, trust_scope
from ..io import resource


def collect(reader: Reader, account: str) -> list:
    summary = (reader.call("get_account_summary") or {}).get("SummaryMap", {})
    policy = reader.call("get_account_password_policy", absent=("NoSuchEntity",))
    values = (policy or {}).get("PasswordPolicy", {})
    facts = {"root_mfa": None, "no_root_key": None, "password_length": None, "password_reuse": None}
    if "AccountMFAEnabled" in summary:
        facts["root_mfa"] = summary["AccountMFAEnabled"] == 1
    if "AccountAccessKeysPresent" in summary:
        facts["no_root_key"] = summary["AccountAccessKeysPresent"] == 0
    if policy is not None:
        facts["password_length"] = values.get("MinimumPasswordLength", 0) >= 14
        facts["password_reuse"] = values.get("PasswordReusePrevention", 0) >= 24
    rows = [resource("account", account, facts)]
    students = []
    for user in reader.rows("list_users", "Users"):
        name = user["UserName"]
        profile = reader.call("get_login_profile", UserName=name, absent=("NoSuchEntity",))
        mfa = None
        if profile == {}:
            mfa = True
        elif profile is not None:
            page = reader.call("list_mfa_devices", UserName=name)
            mfa = None if page is None else bool(page.get("MFADevices"))
            if page and page.get("IsTruncated") and not mfa:
                mfa = None
        tags = (reader.call("list_user_tags", UserName=name) or {}).get("Tags", [])
        flags = labels(tags)
        user_facts = {"console_mfa": mfa}
        if flags.get("low_privilege"):
            students.append(user["Arn"])
            user_facts["self_scoped"] = inline_self(reader, name, user["Arn"])
        rows.append(resource("user", user["Arn"], user_facts, **flags))
    for role in reader.rows("list_roles", "Roles"):
        doc = role.get("AssumeRolePolicyDocument", {})
        statements = doc.get("Statement", []) if isinstance(doc, dict) else []
        if isinstance(statements, dict):
            statements = [statements]
        rows.append(resource("role", role["Arn"], {"trust_statement_count": len(statements),
                             "trust_scoped": trust_scope(doc, role["Arn"], students)}))
    return rows
