#include "qhimdmainwindow.h"
#include "ui_qhimdmainwindow.h"
#include "qhimdaboutdialog.h"
#include "qhimduploaddialog.h"
#include "qmessagebox.h"
#include "qapplication.h"

#include "sony_oma.h"


QString QHiMDMainWindow::dumpmp3(const QHiMDTrack & trk, QString file)
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
        uploadDialog->blockTransferred();
        QApplication::processEvents();
        if(uploadDialog->upload_canceled())
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

QString QHiMDMainWindow::dumpoma(const QHiMDTrack & track, QString file)
{
    QString errmsg;
    struct himd_nonmp3stream str;
    struct himderrinfo status;
    struct trackinfo trkinf;
    unsigned int len;
    const unsigned char * data;
    char header[EA3_FORMAT_HEADER_SIZE];
    QFile f(file);

    if(!f.open(QIODevice::ReadWrite))
        return tr("Error opening file for ATRAC output");

    if(!(errmsg = track.openNonMpegStream(&str)).isNull())
    {
        f.remove();
        return tr("Error opening track: ") + status.statusmsg;
    }

    make_ea3_format_header(header, &trkinf);
    if(f.write(header, sizeof header) == -1)
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
        uploadDialog->blockTransferred();
        QApplication::processEvents();
        if(uploadDialog->upload_canceled())
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


QString QHiMDMainWindow::dumppcm(const QHiMDTrack & track, QString file)
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
      uploadDialog->blockTransferred();
      QApplication::processEvents();
      if(uploadDialog->upload_canceled())
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

void QHiMDMainWindow::checkfile(QString UploadDirectory, QString &filename, QString extension)
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

void QHiMDMainWindow::set_buttons_enable(bool connect, bool download, bool upload, bool rename, bool del, bool format, bool quit)
{
    ui->action_Connect->setEnabled(connect);
    ui->action_Download->setEnabled(download);
    ui->action_Upload->setEnabled(upload);
    ui->action_Rename->setEnabled(rename);
    ui->action_Delete->setEnabled(del);
    ui->action_Format->setEnabled(format);
    ui->action_Quit->setEnabled(quit);
}

void QHiMDMainWindow::init_himd_browser()
{
    ui->TrackList->setModel(&trackmodel);
    ui->TrackList->resizeColumnToContents(0);
    ui->TrackList->resizeColumnToContents(1);
    ui->TrackList->resizeColumnToContents(2);
    ui->TrackList->resizeColumnToContents(3);
    ui->TrackList->resizeColumnToContents(4);
    ui->TrackList->resizeColumnToContents(5);
    ui->TrackList->resizeColumnToContents(6);
}

void QHiMDMainWindow::init_local_browser()
{
    QStringList DownloadFileList;
    localmodel.setFilter(QDir::AllDirs | QDir::Files | QDir::NoDotAndDotDot);
    localmodel.setNameFilters(QStringList() << "*.mp3" << "*.wav" << "*.oma");
    localmodel.setSorting(QDir::DirsFirst | QDir::Name);
    ui->localScan->setModel(&localmodel);
    ui->localScan->setRootIndex(localmodel.index(QDir::rootPath()));
    QModelIndex curdir = localmodel.index(ui->updir->text());
    ui->localScan->expand(curdir);
    ui->localScan->setCurrentIndex(curdir);
    ui->localScan->scrollTo(curdir,QAbstractItemView::PositionAtTop);
    ui->localScan->hideColumn(2);
    ui->localScan->hideColumn(3);
    ui->localScan->setColumnWidth(0, 350);
}

void QHiMDMainWindow::open_himd_at(const QString & path)
{
    QMessageBox himdStatus;
    QString error;

    error = trackmodel.open(path.toAscii());

    if (!error.isNull()) {
        himdStatus.setText(tr("Error opening HiMD data. Make sure you chose the proper root directory of your HiMD-Walkman.\n") + error);
        himdStatus.exec();
        set_buttons_enable(1,0,0,0,0,0,1);
        return;
    }

    ui->himdpath->setText(path);
    settings.setValue("lastHiMDDirectory", path);

    set_buttons_enable(1,1,1,1,1,1,1);
}

void QHiMDMainWindow::upload_to(const QString & UploadDirectory)
{
    QHiMDTrackList tracks = trackmodel.tracks(ui->TrackList->selectionModel()->selectedRows(0));

    int allblocks = 0;
    for(int i = 0;i < tracks.length(); i++)
        allblocks += tracks[i].blockcount();

    uploadDialog->init(tracks.length(), allblocks);
    
    for(int i = 0;i < tracks.length(); i++)
    {
        QString filename, errmsg;
        QString title = tracks[i].title();
        if(title.isNull())
            filename = tr("Track %1").arg(tracks[i].tracknum());
        else
            filename = tracks[i].artist() + " - " + title;

        uploadDialog->starttrack(tracks[i], filename);
        if (!tracks[i].copyprotected())
        {
            QString codec = tracks[i].codecname();
            if (codec == "MPEG")
            {
                checkfile(UploadDirectory, filename, ".mp3");
                errmsg = dumpmp3 (tracks[i], UploadDirectory + "/" + filename + ".mp3");
                if(errmsg.isNull())
                    addid3tag (tracks[i].title(),tracks[i].artist(),tracks[i].album(), UploadDirectory+ "/" +filename + ".mp3");
            }
            else if (codec == "LPCM")
            {
                checkfile(UploadDirectory, filename, ".wav");
                errmsg = dumppcm (tracks[i], UploadDirectory + "/" + filename + ".wav");
            }
            else if (codec == "AT3+" || codec == "AT3 ")
            {
                checkfile(UploadDirectory, filename, ".oma");
                errmsg = dumpoma (tracks[i], UploadDirectory + "/" + filename + ".oma");
            }
        }
        else
            errmsg = tr("upload disabled because of DRM encryption");

        if(errmsg.isNull())
            uploadDialog->trackSucceeded();
        else
            uploadDialog->trackFailed(errmsg);

        QApplication::processEvents();
        if(uploadDialog->upload_canceled())
            break;
    }
    uploadDialog->finished();
    localmodel.refresh();
}

QHiMDMainWindow::QHiMDMainWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::QHiMDMainWindowClass)
{   
    aboutDialog = new QHiMDAboutDialog;
    formatDialog = new QHiMDFormatDialog;
    uploadDialog = new QHiMDUploadDialog;
    ui->setupUi(this);
    ui->updir->setText(settings.value("lastUploadDirectory",
                                         QDir::homePath()).toString());
    set_buttons_enable(1,0,0,0,0,0,1);
    init_himd_browser();
    init_local_browser();
}

QHiMDMainWindow::~QHiMDMainWindow()
{
    delete ui;
}

/* Slots for the actions */

void QHiMDMainWindow::on_action_Download_triggered()
{
    QStringList DownloadFileList;


    DownloadFileList = QFileDialog::getOpenFileNames(
                         this,
                         tr("Select MP3s for download"),
                         "/",
                         "MP3-files (*.mp3)");

}

void QHiMDMainWindow::on_action_Upload_triggered()
{
    QString UploadDirectory = settings.value("lastManualUploadDirectory", QDir::homePath()).toString();
    UploadDirectory = QFileDialog::getExistingDirectory(this,
                                                 tr("Select directory for Upload"),
                                                 UploadDirectory,
                                                 QFileDialog::ShowDirsOnly
                                                 | QFileDialog::DontResolveSymlinks);

    settings.setValue("lastManualUploadDirectory", UploadDirectory);
    upload_to(UploadDirectory);
}

void QHiMDMainWindow::on_action_Quit_triggered()
{
    close();
}

void QHiMDMainWindow::on_action_About_triggered()
{
    aboutDialog->show();
}

void QHiMDMainWindow::on_action_Format_triggered()
{
    formatDialog->show();
}

void QHiMDMainWindow::on_action_Connect_triggered()
{
    QString HiMDDirectory;
    HiMDDirectory = settings.value("lastHiMDDirectory", QDir::rootPath()).toString();
    HiMDDirectory = QFileDialog::getExistingDirectory(this,
                                                 tr("Select directory of HiMD Medium"),
                                                 HiMDDirectory,
                                                 QFileDialog::ShowDirsOnly
                                                 | QFileDialog::DontResolveSymlinks);
    open_himd_at(HiMDDirectory);
}

void QHiMDMainWindow::on_localScan_clicked(QModelIndex index)
{
    if(localmodel.fileInfo(index).isDir())
    {
        ui->updir->setText(localmodel.filePath(index));
        settings.setValue("lastUploadDirectory", localmodel.filePath(index));
    }
}

void QHiMDMainWindow::on_upload_button_clicked()
{
    upload_to(ui->updir->text());
}