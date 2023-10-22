#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "pcap.h"
#include <winsock2.h>
#include "datapackage.h"
#include "readonlydelegate.h"
#include "multithread.h"
#include <QVector>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    void showNetWorkCard();
    int capture();

public slots:
    void HandleMessage(DataPackage data);
private slots:
    void on_comboBox_currentIndexChanged(int index);
    void on_tableWidget_cellClicked(int row, int column);
    void on_lineEdit_returnPressed();
    void on_lineEdit_textChanged(const QString &arg1);
    void on_tableWidget_currentCellChanged(int currentRow, int currentColumn, int previousRow, int previousColumn);
private:
    Ui::MainWindow *ui;
    pcap_if_t *all_device;
    pcap_if_t *device;
    pcap_t *pointer;
    ReadOnlyDelegate *readOnlyDelegate;
    QVector<DataPackage>pData;
    int countNumber;
    char errbuf[PCAP_ERRBUF_SIZE];
    int numberRow;
    bool isStart;
};
#endif // MAINWINDOW_H
