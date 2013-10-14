#!/usr/bin/python
#
# WPA2-Enterprise tests
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import time
import subprocess
import logging
logger = logging.getLogger(__name__)

import hwsim_utils
import hostapd

def eap_connect(dev, method, identity, anonymous_identity=None, password=None,
                phase1=None, phase2=None, ca_cert=None):
    dev.connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap=method,
                identity=identity, anonymous_identity=anonymous_identity,
                password=password, phase1=phase1, phase2=phase2,
                ca_cert=ca_cert,
                wait_connect=False)
    ev = dev.wait_event(["CTRL-EVENT-EAP-STARTED"], timeout=10)
    if ev is None:
        raise Exception("Association and EAP start timed out")
    ev = dev.wait_event(["CTRL-EVENT-EAP-METHOD"], timeout=10)
    if ev is None:
        raise Exception("EAP method selection timed out")
    if method not in ev:
        raise Exception("Unexpected EAP method")
    ev = dev.wait_event(["CTRL-EVENT-EAP-SUCCESS"], timeout=10)
    if ev is None:
        raise Exception("EAP success timed out")
    ev = dev.wait_event(["CTRL-EVENT-CONNECTED"], timeout=10)
    if ev is None:
        raise Exception("Association with the AP timed out")

    status = dev.get_status()
    if status["wpa_state"] != "COMPLETED":
        raise Exception("Connection not completed")
    if status["suppPortStatus"] != "Authorized":
        raise Exception("Port not authorized")
    if method not in status["selectedMethod"]:
        raise Exception("Incorrect EAP method status")
    if status["key_mgmt"] != "WPA2/IEEE 802.1X/EAP":
        raise Exception("Unexpected key_mgmt status")

def test_ap_wpa2_eap_sim(dev, apdev):
    """WPA2-Enterprise connection using EAP-SIM"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], "SIM", "1232010000000000",
                password="90dca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb82581")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])

def test_ap_wpa2_eap_aka(dev, apdev):
    """WPA2-Enterprise connection using EAP-AKA"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], "AKA", "0232010000000000",
                password="90dca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb82581:000000000123")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])

def test_ap_wpa2_eap_aka_prime(dev, apdev):
    """WPA2-Enterprise connection using EAP-AKA'"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], "AKA'", "6555444333222111",
                password="5122250214c33e723a5dd523fc145fc0:981d464c7c52eb6e5036234984ad0bcf:000000000123")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])

def test_ap_wpa2_eap_ttls_pap(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/PAP"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], "TTLS", "pap user",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=PAP")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])

def test_ap_wpa2_eap_ttls_chap(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/CHAP"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], "TTLS", "chap user",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=CHAP")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])

def test_ap_wpa2_eap_ttls_mschap(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/MSCHAP"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], "TTLS", "mschap user",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAP")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])

def test_ap_wpa2_eap_ttls_mschapv2(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/MSCHAPv2"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], "TTLS", "DOMAIN\mschapv2 user",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])

def test_ap_wpa2_eap_ttls_eap_gtc(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/EAP-GTC"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], "TTLS", "user",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.pem", phase2="autheap=GTC")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])

def test_ap_wpa2_eap_ttls_eap_md5(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/EAP-MD5"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], "TTLS", "user",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.pem", phase2="autheap=MD5")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])

def test_ap_wpa2_eap_ttls_eap_mschapv2(dev, apdev):
    """WPA2-Enterprise connection using EAP-TTLS/EAP-MSCHAPv2"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], "TTLS", "user",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.pem", phase2="autheap=MSCHAPV2")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])

def test_ap_wpa2_eap_peap_eap_mschapv2(dev, apdev):
    """WPA2-Enterprise connection using EAP-PEAP/EAP-MSCHAPv2"""
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hostapd.add_ap(apdev[0]['ifname'], params)
    eap_connect(dev[0], "PEAP", "user",
                anonymous_identity="ttls", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2")
    hwsim_utils.test_connectivity(dev[0].ifname, apdev[0]['ifname'])