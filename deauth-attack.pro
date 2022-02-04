TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap

SOURCES += \
    main.cpp

DESTDIR = $${PWD}/bin

HEADERS += \
    auth.h \
    beacon.h \
    deauth.h \
    dot11.h \
    mac.h
