
LIBS += -L/usr/local/lib/ -lpcap
TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
        main.cpp

HEADERS += \
    pcap_arp.h
