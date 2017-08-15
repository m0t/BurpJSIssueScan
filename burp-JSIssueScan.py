from burp import IBurpExtender
from burp import IMessageEditorController
from burp import ITab
from java.awt import Component;
from java.io import PrintWriter;
from java.util import ArrayList;
from java.util import List;
from javax.swing import JScrollPane;
from javax.swing import JSplitPane;
from javax.swing import JTabbedPane;
from javax.swing import JTable;
from javax.swing import JTextArea;
from javax.swing import SwingUtilities;
from javax.swing.table import AbstractTableModel;
from threading import Lock
from java.net import URL
import re


class LibraryEntry:
    def __init__(self, libname):
        self.libname = libname
        self.versions = []
        self.urls = []
        self.cves = []

class IssueParser():
    def __init__(self):
        self.entries = []

    def findEntry(self, libname):
        for e in self.entries:
            if e.libname == libname:
                return e
        return None

    #parse each burp issue 
    def parseIssue(self, issue):
        
        name = issue.getIssueName()
        m=re.search("The JavaScript file '(.*)' includes a vulnerable version of the library '(.*)'", name)
        libname = m.group(2)
        e = self.findEntry(libname)
        if not e:
            print("[+] Found vulnerable lib %s, adding..." % libname)
            e = LibraryEntry(libname)
            self.entries.append(e)
            #print("[+] entries size %d" % len(self.entries))
        
        url = issue.getUrl().toString()
        if url not in e.urls:
            e.urls.append(url)

        details = issue.getIssueDetail()

        m = re.search("The library (.*) version <b>(.*)</b> has known security issues.", details)
        version = m.group(2)
        if version and version not in e.versions:
            e.versions.append(version)

        cves = re.findall("http://www.cvedetails.com/cve/CVE-\d{4}-\d{4}/", details)
        for c in cves:
            if c not in e.cves:
                e.cves.append(c)


    def getLibVulns(self):
        return self.entries

    '''
    [libray name]

    The following outdated versions have been detected in use:
    - [version]
    - [version]
    - ...

    The library includes the following outdated files

    -[url]
    -[url]
    - ...

    CVE Vulnerabilities References:
    - [cvedetails]
    - ...

    '''
    def genReport(self):
        rep = ""
        for e in self.entries:
            rep += "\n%s\n\n" % e.libname
            rep += "The following outdated versions have been detected in use:\n"
            for v in e.versions:
                rep += "- %s\n" % v
            rep += "\nThe library includes the following outdated files:\n"
            for u in e.urls:
                rep += "- %s\n" % u
            if len(e.cves) > 0:
                rep += "\nCVE Vulnerabilities References:\n"
                for cve in e.cves:
                    rep += "- %s\n" % cve

        return rep

class BurpExtender(IBurpExtender, ITab, AbstractTableModel ):

        def registerExtenderCallbacks(self, callbacks):
            self._callbacks = callbacks
            self._helpers = callbacks.getHelpers()
            callbacks.setExtensionName("JS issues processor")
            #callbacks.registerHttpListener(self)

            self._issues = ArrayList()
            #self._lock = Lock()

            # main split pane
            self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
            
            # table of log entries
            logTable = Table(self)
            scrollPane = JScrollPane(logTable)
            self._splitpane.setLeftComponent(scrollPane)

            self._texteditor = callbacks.createTextEditor()

            #self._text = JTextArea(5, 80)
            textpane = JScrollPane(self._texteditor.getComponent())

            self._splitpane.setRightComponent(textpane)

            callbacks.customizeUiComponent(self._splitpane)
            callbacks.customizeUiComponent(logTable)
            #callbacks.customizeUiComponent()
            callbacks.customizeUiComponent(textpane)
            


            callbacks.addSuiteTab(self)

            print("[+] Reading current scanner issues")

            issues = callbacks.getScanIssues("https://www.onthedot.com/")

            ip = IssueParser()

            for i in issues:
                if re.match("^The JavaScript file",i.getIssueName()):
                    #print(i.getIssueName())
                    #print(i.getUrl().toString())

                    ip.parseIssue(i)
                    #self._lock.acquire()
                    row = self._issues.size()
                    self._issues.add(IssueEntry(i) )
                    self.fireTableRowsInserted(row, row)
                    #self._lock.release()

            print("JS Libs Report:")
            print(ip.genReport())

            return

            #
        # implement ITab
        #
        
        def getTabCaption(self):
            return "JS Issues"
        
        def getUiComponent(self):
            return self._splitpane


        #
        # extend AbstractTableModel
        #
        
        def getRowCount(self):
            try:
                return self._issues.size()
            except:
                return 0

        def getColumnCount(self):
            return 2

        def getColumnName(self, columnIndex):
            if columnIndex == 0:
                return "Name"
            if columnIndex == 1:
                return "URL"
            return ""

        def getValueAt(self, rowIndex, columnIndex):
            entry = self._issues.get(rowIndex)
            if columnIndex == 0:
                return entry.getName()
            if columnIndex == 1:
                return entry.getUrl()
            return ""

class Table(JTable):

    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)
        return
    
    def changeSelection(self, row, col, toggle, extend):
    
        # show the  entry for the selected row
        entry = self._extender._issues.get(row)
        self._extender._texteditor.setText(entry.getDetail())
        
        JTable.changeSelection(self, row, col, toggle, extend)
        return

class IssueEntry:
        def __init__(self, issue):
            self._issue = issue
            #self._name = name
            #self._url = url
            return

        def getName(self):
            return self._issue.getIssueName()

        def getUrl(self):
            return self._issue.getUrl().toString()

        def getDetail(self):
            return self._issue.getIssueDetail()