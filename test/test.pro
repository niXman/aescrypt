
TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

QMAKE_CXXFLAGS += \
	-std=c++11

INCLUDEPATH += \
	../include

LIBS += \
	-lcrypto

SOURCES += \
	main.cpp \
	../src/aescrypt.cpp

HEADERS += \
	../include/aescrypt.hpp

