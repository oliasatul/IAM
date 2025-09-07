import streamlit as st
import pandas as pd
import numpy as np
from dateutil import parser
import plotly.express as px

st.set_page_config(page_title="IAM Control Tower (Okta)", layout="wide")

st.title("🔐 IAM Control Tower (Okta)")
st.caption("Upload Okta System Log CSV → get KPIs, charts, and simple alerts.")

uploaded = st.file_uploader("Drop your Okta CSV here", type=["csv"])
if not uploaded:
    st.info("Tip: Use the sample CSV from the instructions to try it out.")
    st.stop()

df = pd.read_csv(uploaded)

# Normalize column names we expect
expected = ["timestamp","eventType","actor","ip","country","mfaUsed","outcome","role"]
missing = [c for c in expected if c not in df.columns]
if missing:
    st.error(f"Missing columns: {missing}\nExpected: {expected}")
    st.stop()

# Parse time
df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
df = df.sort_values("timestamp")

# Basic KPIs
logins = df[df["eventType"].str.contains("user.authentication.succeeded", na=False)]
fails  = df[df["outcome"].str.upper()=="FAILURE"]
mfa    = df[df["eventType"].str.contains("mfa", na=False)]

total_logins = len(logins)
failed_logins = len(fails)
mfa_events = len(mfa)
mfa_fails = len(mfa[mfa["outcome"].str.upper()=="FAILURE"])
mfa_fail_rate = (mfa_fails / mfa_events * 100) if mfa_events else 0

col1, col2, col3, col4 = st.columns(4)
col1.metric("✅ Successful Logins", total_logins)
col2.metric("❌ Failed Logins", failed_logins)
col3.metric("🔐 MFA Events", mfa_events)
col4.metric("⚠️ MFA Fail Rate", f"{mfa_fail_rate:.1f}%")

st.divider()

# Charts
left, right = st.columns(2)
with left:
    fig_ctry = px.bar(df[df["outcome"].str.upper()=="SUCCESS"].groupby("country").size().reset_index(name="logins"),
                      x="country", y="logins", title="Top Countries (Success)")
    st.plotly_chart(fig_ctry, use_container_width=True)

with right:
    fig_ip_fail = px.bar(fails.groupby("ip").size().reset_index(name="fails").sort_values("fails", ascending=False).head(10),
                         x="ip", y="fails", title="Top IPs (Failures)")
    st.plotly_chart(fig_ip_fail, use_container_width=True)

st.divider()

# Simple detections ("good enough" rules)
alerts = []

# 1) Too many failures from a single user in short time (>=3 in 10 min)
df["window10"] = df.groupby("actor")["timestamp"].transform(lambda s: s.rolling("10min").count())
burst = df[(df["outcome"].str.upper()=="FAILURE") & (df["window10"]>=3)]
if not burst.empty:
    users = ", ".join(sorted(set(burst["actor"])))
    alerts.append(f"🚩 Many failures in 10min window: {users}")

# 2) Same user, two countries in 1 hour (possible impossible travel)
def possible_impossible_travel(group):
    group = group.dropna(subset=["country"]).sort_values("timestamp")
    out = []
    for i in range(1, len(group)):
        dt = (group.iloc[i]["timestamp"] - group.iloc[i-1]["timestamp"]).total_seconds()/3600
        if dt <= 1 and group.iloc[i]["country"] != group.iloc[i-1]["country"]:
            out.append((group.iloc[i-1]["country"], group.iloc[i]["country"], group.iloc[i]["timestamp"]))
    return out

imp = []
for actor, g in logins.groupby("actor"):
    hops = possible_impossible_travel(g)
    if hops:
        imp.append(actor)
if imp:
    alerts.append(f"🚩 Country hop within 1 hour: {', '.join(sorted(set(imp)))}")

# 3) Admin login without MFA
admin_success = logins[(logins["role"].str.lower()=="admin")]
admin_no_mfa  = admin_success[admin_success["mfaUsed"].astype(str).str.lower().isin(["false","0","no","na","none",""])]
if not admin_no_mfa.empty:
    who = ", ".join(sorted(set(admin_no_mfa["actor"])))
    alerts.append(f"🚩 Admin success without MFA: {who}")

st.subheader("🚨 Alerts")
if alerts:
    for a in alerts:
        st.warning(a)
else:
    st.success("No alerts found with simple rules.")

st.divider()
st.subheader("Raw Events (filterable)")
with st.expander("Show table"):
    st.dataframe(df, use_container_width=True)
