from .fixtures import BUCKET, LAB, ROLE, USER, snapshot


def lab_state(snap: dict) -> dict:
    inv = snap["inventory"]
    if inv.get("source") != "lab":
        raise ValueError("Only registered classroom snapshots can rebuild the local lab.")
    rows = {r["id"]: r["facts"] for r in inv["resources"]}
    instance = rows[LAB["instance"]]
    flag = instance["imds_safe"]
    if type(flag) is not bool:
        raise ValueError("Incomplete metadata configuration.")
    state = {"bucket_statements": rows[BUCKET]["policy"], "trust": rows[ROLE]["trust"],
             "identity": rows[USER]["identity"], "tokens": "required" if flag else "optional",
             "multi_region": rows["trails/us-east-1"]["active_multi"],
             "role_attachment": instance["role_attachment"]}
    if snapshot(state) != snap:
        raise ValueError("Snapshot cannot reproduce the complete classroom fixture.")
    return state
