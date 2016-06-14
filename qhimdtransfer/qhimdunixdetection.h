#ifndef QHIMDUNIXDETECTION_H
#define QHIMDUNIXDETECTION_H

#include <QtDBus>
#include <qhimddetection.h>

/* define constants for udev */
#define UDISK_SERVICE "org.freedesktop.UDisks2"
#define UDISK_PATH "/org/freedesktop/UDisks2"
#define UDISK_INTERFACE "org.freedesktop.UDisks2"
#define UDISK_PROPERTIES "org.freedesktop.DBus.Properties"
#define UDISK_FILESYSTEM "org.freedesktop.UDisks2.Filesystem"
#define UDISK_DEVICE_PATH "/org/freedesktop/UDisks2/block_devices/"

#define PROP_MOUNTPATH "MountPoints"


/* qhimdtransfer adaptor class, can be accessed through dbus session bus with
 * service=com.trolltech.Qt
 * path=/QHiMDUnixDetection
 * interface=com.trolltech.Qt.QHiMDUnixDetection
 *
 * following methods provided
 * "AddMDDevice" and "RemoveMDDevice"
 * with args: QString deviceFile, int vid, int pid
 */
class QHiMDAdaptor: public QDBusAbstractAdaptor
{
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "com.trolltech.Qt")
    Q_CLASSINFO("D-Bus Introspection", ""
"  <interface name=\"com.trolltech.Qt\">\n"
"    <method name=\"AddMDDevice\">\n"
"      <arg direction=\"in\" type=\"s\" name=\"deviceFile\"/>\n"
"      <arg direction=\"in\" type=\"i\" name=\"vendorId\"/>\n"
"      <arg direction=\"in\" type=\"i\" name=\"productId\"/>\n"
"    </method>\n"
"    <method name=\"RemoveMDDevice\">\n"
"      <arg direction=\"in\" type=\"s\" name=\"deviceFile\"/>\n"
"      <arg direction=\"in\" type=\"i\" name=\"vendorId\"/>\n"
"      <arg direction=\"in\" type=\"i\" name=\"productId\"/>\n"
"    </method>\n"
"  </interface>\n"
        "")
public:
    QHiMDAdaptor(QObject *parent) : QDBusAbstractAdaptor(parent) {}
    virtual ~QHiMDAdaptor() {}
};


class QHiMDUnixDetection : public QHiMDDetection{
    Q_OBJECT

    QHiMDAdaptor *had;
    QDBusConnection dbus_sys;  // system bus connection: needed for getting mountpoint
    QDBusConnection dbus_ses;  // session bus connection: needed for providing method calls AddMDDevice and RemoveMDDevice

public:
    QHiMDUnixDetection(QObject * parent = NULL);
    ~QHiMDUnixDetection() {}
    virtual QString mountpoint(QString devpath);

private:
    QVariant get_property(QString udiskPath, QString property, QString interface);
    QMDDevice *find_by_deviceFile(QString file);
    void add_himddevice(QString file, QString name);
    virtual void remove_himddevice(QString file);

public slots:
    void AddMDDevice(QString deviceFile, int vid, int pid);
    void RemoveMDDevice(QString deviceFile, int vid, int pid);
};

#endif // QHIMDUNIXDETECTION_H
