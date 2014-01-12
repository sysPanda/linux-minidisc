#include <qmddevice.h>
#include <QMessageBox>
#include <QApplication>
#include <QFile>
#include <tlist.h>
#include <fileref.h>
#include <tfile.h>
#include <tag.h>
#include <gcrypt.h>

extern "C" {
#include <sox.h>
}

/* common device members */
QMDDevice::QMDDevice() : dev_type(NO_DEVICE)
{
}

QMDDevice::~QMDDevice()
{
    close();
}

enum device_type QMDDevice::deviceType()
{
    return dev_type;
}

void QMDDevice::setPath(QString path)
{
    device_path = path;
}

QString QMDDevice::path()
{
    return device_path;
}

void QMDDevice::setName(QString name)
{
    recorder_name = name;
}

QString QMDDevice::name()
{
    return recorder_name;
}

void QMDDevice::setBusy(bool busy)
{
    is_busy = busy;
}

bool QMDDevice::isBusy()
{
    return is_busy;
}

void QMDDevice::setMdInserted(bool inserted)
{
    md_inserted = inserted;
}

bool QMDDevice::mdInserted()
{
    return md_inserted;
}

void QMDDevice::setDeviceHandle(void * devicehandle)
{
    devhandle = devicehandle;
}

void * QMDDevice::deviceHandle()
{
    return devhandle;
}

void QMDDevice::registerMdChange(void * regMdChange)
{
    mdChange = regMdChange;
}

void * QMDDevice::MdChange()
{
    return mdChange;
}

QStringList QMDDevice::downloadableFileExtensions() const
{
    if(dev_type == NETMD_DEVICE)
        return QStringList() << "wav";

    if(dev_type == HIMD_DEVICE)
        return QStringList() << "mp3";

    return QStringList();
}

void QMDDevice::checkfile(QString UploadDirectory, QString &filename, QString extension)
{
    QFile f;
    QString newname;
    int i = 2;

    f.setFileName(UploadDirectory + "/" + filename + extension);
    while(f.exists())
    {
        newname = filename + " (" + QString::number(i) + ")";
        f.setFileName(UploadDirectory + "/" + newname + extension);
        i++;
    }
    if(!newname.isEmpty())
        filename = newname;
}


/* netmd device members */
QNetMDDevice::QNetMDDevice()
{
    dev_type = NETMD_DEVICE;
    devh = NULL;
    netmd = NULL;
    is_open = false;
}

QNetMDDevice::~QNetMDDevice()
{
    close();
}

void QNetMDDevice::setUsbDevice(netmd_device * dev)
{
    netmd = dev;
}

QString QNetMDDevice::open()
{
    uint8_t i = 0;
    netmd_error error;
    char buffer[256];

    if(!netmd)
        return tr("netmd_device not set, use setUsbDevice() function first");

    if((error = netmd_open(netmd, &devh)) != NETMD_NO_ERROR)
        return tr("Error opening netmd: %1").arg(netmd_strerror(error));

    netmd_initialize_disc_info(devh, &current_md);

    /* generate track count first, needed by QNetMDTracksModel */
    while(netmd_request_title(devh, i, buffer, sizeof(buffer)) >= 0)
        i++;

    trk_count = i;

    is_open = true;
    md_inserted = true;
    emit opened();
    return QString();
}

void QNetMDDevice::close()
{
    if(!devh)
        return;

    netmd_clean_disc_info(&current_md);
    netmd_close(devh);
    devh = NULL;

    is_open = false;
    trk_count = 0;
    md_inserted = false;
    emit closed();
}

QString QNetMDDevice::discTitle()
{
    return QString(current_md.groups[0].name);
}

QNetMDTrack QNetMDDevice::netmdTrack(unsigned int trkindex)
{
    return QNetMDTrack(devh, &current_md, trkindex);
}

/* to be freed !*/
QMDTrack *QNetMDDevice::track(unsigned int trkindex)
{
    return new QNetMDTrack(devh, &current_md, trkindex);
}

QString QNetMDDevice::upload_track_blocks(uint32_t length, FILE *file, size_t chunksize)
{
    /* this is a copy of netmd_secure_real_recv_track(...) function, but updates upload dialog progress bar */
    uint32_t done = 0;
    unsigned char *data;
    int status;
    netmd_error error = NETMD_NO_ERROR;
    int transferred = 0;

    data = (unsigned char *)malloc(chunksize);
    while (done < length) {
        if ((length - done) < chunksize) {
            chunksize = length - done;
        }

        status = libusb_bulk_transfer((libusb_device_handle*)devh, 0x81, data, (int)chunksize, &transferred, 10000);

        if (status >= 0) {
            done += transferred;
            fwrite(data, transferred, 1, file);
            netmd_log(NETMD_LOG_DEBUG, "%.1f%%\n", (double)done/(double)length * 100);

            uploadDialog.blockTransferred();
            QApplication::processEvents();
            /* do not check for uploadDialog.upload_canceled() here, netmd device will remain busy if track upload hasn´t finished */
        }
        else if (status != -LIBUSB_ERROR_TIMEOUT) {
            error = NETMD_USB_ERROR;
        }
    }
    free(data);

    return (error != NETMD_NO_ERROR) ? netmd_strerror(error) : QString();
}

void QNetMDDevice::upload(unsigned int trackidx, QString path)
{
    /* this is a copy of netmd_secure_recv_track(...) function, we need single block transfer function to make use of a progress bar,
     * maybe we can add/change something inside libnetmd for this
     */
    QNetMDTrack track = netmdTrack(trackidx);
    uint16_t track_id = trackidx;
    unsigned char cmdhdr[] = {0x00, 0x10, 0x01};
    unsigned char cmd[sizeof(cmdhdr) + sizeof(track_id)] = { 0 };
    unsigned char *buf;
    unsigned char codec;
    uint32_t length;
    netmd_response response;
    netmd_error error;
    QString filename, errmsg, filepath;
    FILE * file = NULL;

    if(name() != "SONY MZ-RH1 (NetMD)")
    {
        errmsg = tr("upload disabled, %1 does not support netmd track uploads").arg(name());
        goto clean;
    }

    if(track.copyprotected())
    {
        errmsg = tr("upload disabled, Track is copy protected");
        goto clean;
    }

    // create filename first
    if(track.title().isEmpty())
        filename = tr("Track %1").arg(track.tracknum() + 1);
    else
        filename = track.title();

    if(track.bitrate_id == NETMD_ENCODING_SP) {
        checkfile(path, filename, ".aea");
        filepath = path + "/" + filename + ".aea";
    }
    else {
        checkfile(path, filename, ".wav");
        filepath = path + "/" + filename + ".wav";
    }

    if(!(file = fopen(filepath.toUtf8().data(), "wb"))) {
            errmsg = tr("cannot open file %1 for writing").arg(filepath);
            goto clean;
    }

    buf = cmd;
    memcpy(buf, cmdhdr, sizeof(cmdhdr));
    buf += sizeof(cmdhdr);
    netmd_copy_word_to_buffer(&buf, trackidx + 1U, 0);

    netmd_send_secure_msg(devh, 0x30, cmd, sizeof(cmd));
    error = netmd_recv_secure_msg(devh, 0x30, &response, NETMD_STATUS_INTERIM);
    netmd_check_response_bulk(&response, cmdhdr, sizeof(cmdhdr), &error);
    netmd_check_response_word(&response, track_id + 1U, &error);
    codec = netmd_read(&response);
    length = netmd_read_doubleword(&response);

    /* initialize track.blockcount() here, needed by progress bar in the uploadDialog */
    track.setBlocks(length%NETMD_RECV_BUF_SIZE ? length / NETMD_RECV_BUF_SIZE + 1 : length / NETMD_RECV_BUF_SIZE);
    uploadDialog.starttrack(track, filename);
    if (track.bitrate_id == NETMD_ENCODING_SP) {
        netmd_write_aea_header(track.title().toUtf8().data(), codec, track.channel, file);
    }
    else {
        netmd_write_wav_header(codec, length, file);
    }

    errmsg = upload_track_blocks(length, file, NETMD_RECV_BUF_SIZE);
    if(!errmsg.isNull()) {
        goto clean;
    }

    error = netmd_recv_secure_msg(devh, 0x30, &response, NETMD_STATUS_ACCEPTED);
    netmd_check_response_bulk(&response, cmdhdr, sizeof(cmdhdr), &error);
    netmd_read_response_bulk(&response, NULL, 2, &error);
    netmd_check_response_word(&response, 0, &error);

    if(error != NETMD_NO_ERROR)
        errmsg = QString(netmd_strerror(error));

clean:
    if(errmsg.isNull())
        uploadDialog.trackSucceeded();
    else
        uploadDialog.trackFailed(errmsg);

    if(file)
        fclose(file);
    if(!errmsg.isNull())
    {
        QFile f(filepath);
        if(f.exists())
            f.remove();
    }
}

void QNetMDDevice::batchUpload(QMDTrackIndexList tlist, QString path)
{
    int allblocks = 0;

    setBusy(true);

    /* progress bar for all tracks does not work yet, is there any way to get track length without recieving a complete track ?
     * as far as i´ve tested device remains busy if download procedure hasn´t finished.
     * progressbar for all tracks shows idle mode if maximum value is set to 0
     */
    for(int i = 0;i < tlist.length(); i++) {
        allblocks += netmdTrack(tlist.at(i)).blockcount();
    }

    uploadDialog.init(tlist.length(), allblocks);

    for(int i = 0; i < tlist.length(); i++) {
        upload(tlist[i], path);
        QApplication::processEvents();
        if(uploadDialog.upload_canceled())
            break;
    }

    uploadDialog.finished();
    setBusy(false);
}

void QNetMDDevice::retailmac(unsigned char *rootkey, unsigned char *hostnonce,
               unsigned char *devnonce, unsigned char *sessionkey)
{
    gcry_cipher_hd_t handle1;
    gcry_cipher_hd_t handle2;

    unsigned char des3_key[24] = { 0 };
    unsigned char iv[8] = { 0 };

    gcry_cipher_open(&handle1, GCRY_CIPHER_DES, GCRY_CIPHER_MODE_ECB, 0);
    gcry_cipher_setkey(handle1, rootkey, 8);
    gcry_cipher_encrypt(handle1, iv, 8, hostnonce, 8);

    memcpy(des3_key, rootkey, 16);
    memcpy(des3_key+16, rootkey, 8);
    gcry_cipher_open(&handle2, GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_CBC, 0);
    gcry_cipher_setkey(handle2, des3_key, 24);
    gcry_cipher_setiv(handle2, iv, 8);
    gcry_cipher_encrypt(handle2, sessionkey, 8, devnonce, 8);

    gcry_cipher_close(handle1);
    gcry_cipher_close(handle2);
}

/* setting up a secure session until sessionkey generation */
QString QNetMDDevice::prepare_download(netmd_dev_handle * devh, unsigned char * sky)
{

    netmd_error error;
    netmd_ekb ekb;
    netmd_keychain *keychain;
    netmd_keychain *next;
    size_t done;
    static unsigned char chain[] = {0x25, 0x45, 0x06, 0x4d, 0xea, 0xca,
                             0x14, 0xf9, 0x96, 0xbd, 0xc8, 0xa4,
                             0x06, 0xc2, 0x2b, 0x81, 0x49, 0xba,
                             0xf0, 0xdf, 0x26, 0x9d, 0xb7, 0x1d,
                             0x49, 0xba, 0xf0, 0xdf, 0x26, 0x9d,
                             0xb7, 0x1d};
    static unsigned char signature[] = {0xe8, 0xef, 0x73, 0x45, 0x8d, 0x5b,
                                 0x8b, 0xf8, 0xe8, 0xef, 0x73, 0x45,
                                 0x8d, 0x5b, 0x8b, 0xf8, 0x38, 0x5b,
                                 0x49, 0x36, 0x7b, 0x42, 0x0c, 0x58};
    static unsigned char rootkey[] = {0x13, 0x37, 0x13, 0x37, 0x13, 0x37,
                               0x13, 0x37, 0x13, 0x37, 0x13, 0x37,
                               0x13, 0x37, 0x13, 0x37};
    static unsigned char hostnonce[8] = { 0 };
    static unsigned char devnonce[8] = { 0 };

    if((error = netmd_secure_leave_session(devh)) != NETMD_NO_ERROR)
        return tr("netmd_secure_leave_session: %1").arg(netmd_strerror(error));

    if((error = netmd_secure_set_track_protection(devh, 0x01)) != NETMD_NO_ERROR)
        return tr("netmd_secure_set_track_protection: %1").arg(netmd_strerror(error));

    if((error = netmd_secure_enter_session(devh)) != NETMD_NO_ERROR)
        return tr("netmd_secure_enter_session: %1").arg(netmd_strerror(error));

    /* build ekb */
    ekb.id = 0x26422642;
    ekb.depth = 9;
    ekb.signature = (char *)malloc(sizeof(signature));
    memcpy(ekb.signature, signature, sizeof(signature));

    /* build ekb key chain */
    ekb.chain = NULL;
    for (done = 0; done < sizeof(chain); done+=16U)
    {
        next = (netmd_keychain *)malloc(sizeof(netmd_keychain));
        if (ekb.chain == NULL) {
            ekb.chain = next;
        }
        else {
            keychain->next = next;
        }
        next->next = NULL;

        next->key = (char *)malloc(16);
        memcpy(next->key, chain + done, 16);

        keychain = next;
    }

    if((error = netmd_secure_send_key_data(devh, &ekb)) != NETMD_NO_ERROR)
        return tr("netmd_secure_send_key_data: %1").arg(netmd_strerror(error));

    /* cleanup */
    free(ekb.signature);
    keychain = ekb.chain;
    while (keychain != NULL) {
        next = keychain->next;
        free(keychain->key);
        free(keychain);
        keychain = next;
    }

    /* exchange nonces */
    gcry_create_nonce(hostnonce, sizeof(hostnonce));

    if((error = netmd_secure_session_key_exchange(devh, hostnonce, devnonce)) != NETMD_NO_ERROR)
        return tr("netmd_secure_session_key_exchange: %1").arg(netmd_strerror(error));

    /* calculate session key */
    retailmac(rootkey, hostnonce, devnonce, sky);

    return QString();
}

void QNetMDDevice::download(QString audiofile, QString title)
{
    /* as chunk size in the netmd_packet(s) is very large, progress bar is not really usable,
     * just inform the user with a message box for now
     */

    QMessageBox downloadBox;
    QString errmsg;
    netmd_error error;
    static unsigned char sessionkey[8] = { 0 };
    static unsigned char kek[] = { 0x14, 0xe3, 0x83, 0x4e, 0xe2, 0xd3, 0xcc, 0xa5 };
    static unsigned char contentid[] = { 0x01, 0x0F, 0x50, 0x00, 0x00, 0x04,
                                  0x00, 0x00, 0x00, 0x48, 0xA2, 0x8D,
                                  0x3E, 0x1A, 0x3B, 0x0C, 0x44, 0xAF,
                                  0x2f, 0xa0 };

    netmd_track_packets *packets = NULL;
    size_t packet_count = 0;

    uint16_t track;
    unsigned char uuid[8] = { 0 };
    unsigned char new_contentid[20] = { 0 };

    netmd_wave_track trk;

    downloadBox.setWindowTitle(tr("Downloading file to %1").arg(name()));
    downloadBox.setIconPixmap(QPixmap(":icons/download_to_md.png"));
    downloadBox.setText(tr("Please wait while transferring audio file\n%1").arg(audiofile));
    downloadBox.setStandardButtons(0);
    downloadBox.show();
    /* call processEvents() periodically to show up message box correctly */
    QApplication::processEvents();

    /* read audio file and set wireformat, diskformat and byteorder conversion correctly*/
    if((error = netmd_wave_track_init(audiofile.toUtf8(), &trk)) != NETMD_NO_ERROR)
    {
        errmsg = tr("Error:\nnetmd_wave_track_init: %1").arg(netmd_strerror(error));
        goto clean;
    }
    QApplication::processEvents();

    /* byte order conversion if needed*/
    if(trk.bo_conv)
    {
        for(unsigned int i = 0; i < trk.audiosize; i+=2)
        {
            unsigned char first = trk.rawdata[i];
            trk.rawdata[i] = trk.rawdata[i+1];
            trk.rawdata[i+1] = first;
        }
    }
    QApplication::processEvents();

    /* init a secure session */
    if(!(errmsg = prepare_download(devh, sessionkey)).isEmpty())
    {
        errmsg = tr("Error:\n%1").arg(errmsg);
        netmd_wave_track_free(&trk);
        goto clean;
    }
    QApplication::processEvents();

    /* prepare download operation*/
    if((error = netmd_secure_setup_download(devh, contentid, kek, sessionkey)) != NETMD_NO_ERROR)
    {
        errmsg = tr("Error:\nnetmd_secure_setup_download: %1").arg(netmd_strerror(error));
        netmd_wave_track_free(&trk);
        goto clean;
    }
    QApplication::processEvents();

    /* setup data packet(s) and get number of frames stored in the packet(s)*/
    if((error = netmd_prepare_packets(&trk, &packets, &packet_count, kek)) != NETMD_NO_ERROR)
    {
        errmsg = tr("Error:\nnetmd_prepare_packets: %1").arg(netmd_strerror(error));
        netmd_cleanup_packets(&packets);
        netmd_wave_track_free(&trk);
        goto clean;
    }
    QApplication::processEvents();

    /* send track to device*/
    error = netmd_secure_send_track(devh, trk.wireformat,
                                    trk.diskformat,
                                    trk.frames, packets,
                                    packet_count, sessionkey,
                                    &track, uuid, new_contentid);
    /* cleanup */
    netmd_cleanup_packets(&packets);
    netmd_wave_track_free(&trk);

    if(error != NETMD_NO_ERROR)
    {
        errmsg = tr("Error:\nnetmd_secure_send_track: %1").arg(netmd_strerror(error));
        goto clean;
    }

    /* set title */
    netmd_cache_toc(devh);
    netmd_set_title(devh, track, title.toUtf8());
    netmd_sync_toc(devh);

    /* commit track */
    if((error = netmd_secure_commit_track(devh, track, sessionkey)) != NETMD_NO_ERROR)
        errmsg = tr("Error:\nnetmd_secure_commit_track: %1").arg(netmd_strerror(error));

clean:
    /* forget key */
    netmd_secure_session_key_forget(devh);
    /* leave session */
    netmd_secure_leave_session(devh);

    if(errmsg.isEmpty())
        errmsg = tr("Download finished.\n\nsuccessfully transferred audio file\n   %1\nto disk at track number %2").arg(audiofile).arg(track+1);
    downloadBox.close();
    downloadBox.setText(errmsg);
    downloadBox.setStandardButtons(QMessageBox::Ok);
    downloadBox.exec();
}


/* himd device members */

QHiMDDevice::QHiMDDevice()
{
    dev_type = HIMD_DEVICE;
    himd = NULL;
    is_open = false;
}

QHiMDDevice::~QHiMDDevice()
{
    close();
}

QString QHiMDDevice::open()
{
    struct himderrinfo status;

    if(!mdInserted())
        return tr("cannot open device, no disc");

    if(himd)  // first close himd if opened
    {
        himd_close(himd);
        delete himd;
        himd = NULL;
    }

    himd = new struct himd;
    if(himd_open(himd, device_path.toUtf8(), &status) < 0)
    {
        delete himd;
        himd = NULL;
        return QString::fromUtf8(status.statusmsg);
    }

    trk_count = himd_track_count(himd);
    is_open = true;
    md_inserted = true;
    emit opened();
    return QString();
}

void QHiMDDevice::close()
{
    if(!himd)
        return;

    himd_close(himd);
    delete himd;
    himd = NULL;

    is_open = false;
    trk_count = 0;
    emit closed();
}

QHiMDTrack QHiMDDevice::himdTrack(unsigned int trkindex)
{
    return QHiMDTrack(himd, trkindex);
}

QString QHiMDDevice::dumpmp3(const QHiMDTrack &trk, QString file)
{
    QString errmsg;
    struct himd_mp3stream str;
    struct himderrinfo status;
    unsigned int len;
    const unsigned char * data;
    QFile f(file);

    if(!f.open(QIODevice::ReadWrite))
    {
        return tr("Error opening file for MP3 output");
    }
    if(!(errmsg = trk.openMpegStream(&str)).isNull())
    {
        f.remove();
        return tr("Error opening track: ") + errmsg;
    }
    while(himd_mp3stream_read_block(&str, &data, &len, NULL, &status) >= 0)
    {
        if(f.write((const char*)data,len) == -1)
        {
            errmsg = tr("Error writing audio data");
            goto clean;
        }
        uploadDialog.blockTransferred();
        QApplication::processEvents();
        if(uploadDialog.upload_canceled())
        {
            errmsg = tr("upload aborted by the user");
            goto clean;
        }

    }
    if(status.status != HIMD_STATUS_AUDIO_EOF)
        errmsg = tr("Error reading audio data: ") + status.statusmsg;

clean:
    f.close();
    himd_mp3stream_close(&str);
    if(!errmsg.isNull())
        f.remove();
    return errmsg;
}

static inline TagLib::String QStringToTagString(const QString & s)
{
    return TagLib::String(s.toUtf8().data(), TagLib::String::UTF8);
}

static void addid3tag(QString title, QString artist, QString album, QString file)
{
#ifdef Q_OS_WIN
    TagLib::FileRef f(file.toStdWString().c_str());
#else
    TagLib::FileRef f(file.toUtf8().data());
#endif
    TagLib::Tag *t = f.tag();
    t->setTitle(QStringToTagString(title));
    t->setArtist(QStringToTagString(artist));
    t->setAlbum(QStringToTagString(album));
    t->setComment("*** imported from HiMD via QHiMDTransfer ***");
    f.file()->save();
}

QString QHiMDDevice::dumpoma(const QHiMDTrack &track, QString file)
{
    QString errmsg;
    struct himd_nonmp3stream str;
    struct himderrinfo status;
    unsigned int len;
    const unsigned char * data;
    QFile f(file);

    if(!f.open(QIODevice::ReadWrite))
        return tr("Error opening file for ATRAC output");

    if(!(errmsg = track.openNonMpegStream(&str)).isNull())
    {
        f.remove();
        return tr("Error opening track: ") + status.statusmsg;
    }

    if(f.write(track.makeEA3Header()) == -1)
    {
        errmsg = tr("Error writing header");
        goto clean;
    }
    while(himd_nonmp3stream_read_block(&str, &data, &len, NULL, &status) >= 0)
    {
        if(f.write((const char*)data,len) == -1)
        {
            errmsg = tr("Error writing audio data");
            goto clean;
        }
        uploadDialog.blockTransferred();
        QApplication::processEvents();
        if(uploadDialog.upload_canceled())
        {
            errmsg = QString("upload aborted by the user");
            goto clean;
        }
    }
    if(status.status != HIMD_STATUS_AUDIO_EOF)
        errmsg = QString("Error reading audio data: ") + status.statusmsg;

clean:
    f.close();
    himd_nonmp3stream_close(&str);

    if(!errmsg.isNull())
        f.remove();
    return errmsg;
}

QString QHiMDDevice::dumppcm(const QHiMDTrack &track, QString file)
{
    struct himd_nonmp3stream str;
    struct himderrinfo status;
    unsigned int len, i;
    int left, right;
    int clipcount;
    QString errmsg;
    QFile f(file);
    const unsigned char * data;
    sox_format_t * out;
    sox_sample_t soxbuf [HIMD_MAX_PCMFRAME_SAMPLES * 2];
    sox_signalinfo_t signal_out;

    signal_out.channels = 2;
    signal_out.length = 0;
    signal_out.precision = 16;
    signal_out.rate = 44100;

    if(!(out = sox_open_write(file.toUtf8(), &signal_out, NULL, NULL, NULL, NULL)))
        return tr("Error opening file for WAV output");

    if(!(errmsg = track.openNonMpegStream(&str)).isNull())
    {
        f.remove();
        return tr("Error opening track: ") + status.statusmsg;
    }

    while(himd_nonmp3stream_read_block(&str, &data, &len, NULL, &status) >= 0)
    {

      for(i = 0; i < len/4; i++) {

        left = data[i*4]*256+data[i*4+1];
        right = data[i*4+2]*256+data[i*4+3];
        if (left > 0x8000) left -= 0x10000;
        if (right > 0x8000) right -= 0x10000;

        soxbuf[i*2] = SOX_SIGNED_16BIT_TO_SAMPLE(left, clipcount);
        soxbuf[i*2+1] = SOX_SIGNED_16BIT_TO_SAMPLE(right, clipcount);
        (void)clipcount; /* suppess "is unused" warning */
      }

      if (sox_write(out, soxbuf, len/2) != len/2)
      {
            errmsg = tr("Error writing audio data");
            goto clean;
      }
      uploadDialog.blockTransferred();
      QApplication::processEvents();
      if(uploadDialog.upload_canceled())
      {
            errmsg = QString("upload aborted by the user");
            goto clean;
      }
    }
    if(status.status != HIMD_STATUS_AUDIO_EOF)
        errmsg = QString("Error reading audio data: ") + status.statusmsg;

clean:
    sox_close(out);
    himd_nonmp3stream_close(&str);

    if(!errmsg.isNull())
        f.remove();
    return errmsg;
}

void QHiMDDevice::upload(unsigned int trackidx, QString path)
{
    QString filename, errmsg;
    QHiMDTrack track = himdTrack(trackidx);
    QString title = track.title();

    if(title.isNull())
        filename = tr("Track %1").arg(track.tracknum()+1);
    else
        filename = track.artist() + " - " + title;

    uploadDialog.starttrack(track, filename);
    if (!track.copyprotected())
    {
        QString codec = track.codecname();
        if (codec == "MPEG")
        {
            checkfile(path, filename, ".mp3");
            errmsg = dumpmp3 (track, path + "/" + filename + ".mp3");
            if(errmsg.isNull())
                addid3tag (track.title(),track.artist(),track.album(), path + "/" +filename + ".mp3");
        }
        else if (codec == "LPCM")
        {
            checkfile(path, filename, ".wav");
            errmsg = dumppcm (track, path + "/" + filename + ".wav");
        }
        else if (codec == "AT3+" || codec == "AT3 ")
        {
            checkfile(path, filename, ".oma");
            errmsg = dumpoma (track, path + "/" + filename + ".oma");
        }
    }
    else
        errmsg = tr("upload disabled because of DRM encryption");

    if(errmsg.isNull())
        uploadDialog.trackSucceeded();
    else
        uploadDialog.trackFailed(errmsg);

}

void QHiMDDevice::batchUpload(QMDTrackIndexList tlist, QString path)
{
    int allblocks = 0;

    setBusy(true);

    for(int i = 0;i < tlist.length(); i++)
        allblocks += himdTrack(tlist.at(i)).blockcount();

    uploadDialog.init(tlist.length(), allblocks);

    for(int i = 0; i < tlist.length(); i++) {
        upload(tlist[i], path);
        QApplication::processEvents();
        if(uploadDialog.upload_canceled())
            break;
    }

    uploadDialog.finished();
    setBusy(false);
}
