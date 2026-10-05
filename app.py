import streamlit as st

from database.db import initialize_database


initialize_database()


st.set_page_config(
    page_title="Network Traffic Monitor",
    page_icon="Network",
    layout="wide"
)


st.title("Network Traffic Monitoring and Analysis System")

st.write(
    "A Python-based application for monitoring and analyzing "
    "network traffic."
)

st.info(
    "Use this application only on networks and devices that you "
    "own or are authorized to monitor."
)