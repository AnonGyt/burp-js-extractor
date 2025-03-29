from burp import IBurpExtender, ITab, IHttpListener, IContextMenuFactory
from javax.swing import JPanel, JButton, JTextField, JLabel, BoxLayout, JTable, JScrollPane, JMenuItem, JOptionPane, JFileChooser
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, Dimension
from java.io import File, FileWriter
import re
import os

class BurpExtender(IBurpExtender, ITab, IHttpListener, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        # Initialize variables
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.js_files = []
        self.tableData = []
        self.tableColumns = ["#", "URL", "Status", "Size (bytes)", "In Scope"]
        
        # Set extension name
        callbacks.setExtensionName("JS File Extractor")
        
        # Register as a listener
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)
        
        # Create UI
        self._panel = JPanel()
        self._panel.setLayout(BoxLayout(self._panel, BoxLayout.Y_AXIS))
        
        # Add controls panel
        controlsPanel = JPanel()
        controlsPanel.setLayout(BoxLayout(controlsPanel, BoxLayout.X_AXIS))
        
        # Add extract button
        self.extractButton = JButton("Extract JS Files", actionPerformed=self.extractJSFiles)
        controlsPanel.add(self.extractButton)
        
        # Add export button
        self.exportButton = JButton("Export to File", actionPerformed=self.exportToFile)
        controlsPanel.add(self.exportButton)
        
        # Add clear button
        self.clearButton = JButton("Clear Table", actionPerformed=self.clearTable)
        controlsPanel.add(self.clearButton)
        
        # Add scope filter checkbox
        self.inScopeOnlyLabel = JLabel("In-scope items only")
        controlsPanel.add(self.inScopeOnlyLabel)
        
        self._panel.add(controlsPanel)
        
        # Add results table
        self.tableModel = DefaultTableModel(self.tableData, self.tableColumns)
        self.table = JTable(self.tableModel)
        scrollPane = JScrollPane(self.table)
        scrollPane.setPreferredSize(Dimension(800, 400))
        self._panel.add(scrollPane)
        
        # Add the tab to Burp's UI
        callbacks.addSuiteTab(self)
        
        print("JS File Extractor loaded successfully!")
    
    # Implement ITab methods
    def getTabCaption(self):
        return "JS Extractor"
    
    def getUiComponent(self):
        return self._panel
    
    # Extract JS files from proxy history
    def extractJSFiles(self, event):
        self.js_files = []
        self.tableData = []
        self.tableModel.setRowCount(0)
        
        # Get proxy history
        proxyHistory = self._callbacks.getProxyHistory()
        count = 0
        
        for request in proxyHistory:
            # Get request info
            requestInfo = self._helpers.analyzeRequest(request)
            url = requestInfo.getUrl().toString()
            
            # Check if it's a JS file
            if url.endswith('.js') or '.js?' in url:
                # Check if URL is in scope
                isInScope = self._callbacks.isInScope(requestInfo.getUrl())
                
                # Get response info
                response = request.getResponse()
                if response:
                    responseInfo = self._helpers.analyzeResponse(response)
                    statusCode = responseInfo.getStatusCode()
                    responseSize = len(response) - responseInfo.getBodyOffset()
                    
                    # Add to list
                    self.js_files.append({
                        'url': url,
                        'status': statusCode,
                        'size': responseSize,
                        'in_scope': isInScope,
                        'response': response
                    })
                    
                    # Add to table if in scope
                    if isInScope:
                        count += 1
                        self.tableModel.addRow([count, url, statusCode, responseSize, "Yes"])
        
        if count == 0:
            JOptionPane.showMessageDialog(None, "No in-scope JavaScript files found in proxy history.")
        else:
            JOptionPane.showMessageDialog(None, "Found {} in-scope JavaScript files!".format(count))
    
    # Export results to file
    def exportToFile(self, event):
        if len(self.js_files) == 0:
            JOptionPane.showMessageDialog(None, "No JavaScript files to export. Run extraction first.")
            return
        
        # Create file chooser
        fileChooser = JFileChooser()
        fileChooser.setDialogTitle("Select Export Directory")
        fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
        
        # Show dialog
        result = fileChooser.showSaveDialog(self._panel)
        
        if result == JFileChooser.APPROVE_OPTION:
            directory = fileChooser.getSelectedFile().getAbsolutePath()
            exportCount = 0
            inScopeCount = 0
            duplicateCount = 0
            errorCount = 0
            filenames_seen = set()
            
            # Export files
            for js_file in self.js_files:
                if js_file['in_scope']:
                    inScopeCount += 1
                    try:
                        # Create sanitized filename
                        url = js_file['url']
                        filename = self.sanitize_filename(url)
                        
                        # Check for duplicates
                        if filename in filenames_seen:
                            duplicateCount += 1
                            # Append a unique identifier to make filename unique
                            base, ext = os.path.splitext(filename)
                            filename = "{}_{:03d}{}".format(base, duplicateCount, ext)
                        
                        filenames_seen.add(filename)
                        
                        # Get JS content
                        response = js_file['response']
                        responseInfo = self._helpers.analyzeResponse(response)
                        bodyOffset = responseInfo.getBodyOffset()
                        body = response[bodyOffset:]
                        
                        # Write to file
                        filePath = os.path.join(directory, filename)
                        with open(filePath, 'wb') as f:
                            f.write(body)
                        
                        exportCount += 1
                    except Exception as e:
                        print("Error exporting {}: {}".format(url, str(e)))
                        errorCount += 1
            
            # Show detailed stats
            message = "Stats:\n"
            message += "Total JS files: {}\n".format(len(self.js_files))
            message += "In-scope files: {}\n".format(inScopeCount)
            message += "Successfully exported: {}\n".format(exportCount)
            message += "Duplicates renamed: {}\n".format(duplicateCount)
            message += "Errors during export: {}\n".format(errorCount)
            JOptionPane.showMessageDialog(None, message)
    
    # Clear the table
    def clearTable(self, event):
        self.tableModel.setRowCount(0)
        self.js_files = []
    
    # Create a valid filename from URL
    def sanitize_filename(self, url):
        # Remove protocol and domain
        filename = re.sub(r'^https?://', '', url)
        
        # Replace special characters
        filename = re.sub(r'[\\/*?:"<>|]', '_', filename)
        
        # Replace URL characters
        filename = filename.replace('/', '_').replace('&', '_').replace('?', '_')
        
        # Keep length reasonable
        if len(filename) > 200:
            filename = filename[-200:]
        
        # Ensure it ends with .js
        if not filename.endswith('.js'):
            filename += '.js'
            
        return filename
    
    # IHttpListener implementation
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # We'll just use this to listen for requests, but the main functionality 
        # is implemented via the extract button to avoid performance issues
        pass
    
    # IContextMenuFactory implementation
    def createMenuItems(self, invocation):
        menuItems = []
        menuItem = JMenuItem("Send to JS Extractor", actionPerformed=lambda x: self.sendToExtractor(invocation))
        menuItems.append(menuItem)
        return menuItems
    
    # Add selected request to the table
    def sendToExtractor(self, invocation):
        messages = invocation.getSelectedMessages()
        count = self.tableModel.getRowCount() + 1
        
        for message in messages:
            requestInfo = self._helpers.analyzeRequest(message)
            url = requestInfo.getUrl().toString()
            
            if url.endswith('.js') or '.js?' in url:
                # Check if URL is in scope
                isInScope = self._callbacks.isInScope(requestInfo.getUrl())
                
                # Get response info
                response = message.getResponse()
                if response:
                    responseInfo = self._helpers.analyzeResponse(response)
                    statusCode = responseInfo.getStatusCode()
                    responseSize = len(response) - responseInfo.getBodyOffset()
                    
                    # Add to list
                    self.js_files.append({
                        'url': url,
                        'status': statusCode,
                        'size': responseSize,
                        'in_scope': isInScope,
                        'response': response
                    })
                    
                    # Add to table
                    if isInScope:
                        self.tableModel.addRow([count, url, statusCode, responseSize, "Yes"])
                        count += 1