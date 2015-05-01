GetComStats

Public Shared Function GetCOMStats(ByVal sComponentGUID As String) As Integer
            Dim bComponentFound As Boolean = False
            Dim retVal As New ArrayList
            Dim appDataPtr As IntPtr = IntPtr.Zero
            Dim aAppData As IntPtr
            Dim getAppData As COMSVCSLib.IGetAppData

            Dim gh As GCHandle = GCHandle.Alloc(aAppData, GCHandleType.Pinned)
            Dim AddrOfaAppData As IntPtr = gh.AddrOfPinnedObject

            Try
                ' Get an instance of the internal com+ tracker objet 
                Dim comPlusTrackerType As COMSVCSLib.TrackerServer
                comPlusTrackerType = New COMSVCSLib.TrackerServer
                getAppData = comPlusTrackerType

                'get an array of the running COM+ applications
                Dim appCount As UInteger
                getAppData.GetApps(appCount, AddrOfaAppData)
                If appCount = 0 Then Return 0

                'step through the list of running applications
                aAppData = New IntPtr(Marshal.ReadInt32(AddrOfaAppData))
                Dim appDataSize As Integer = Marshal.SizeOf(GetType(COMSVCSLib.appData))
                Dim appIndex As Int32
                For appIndex = 0 To appCount Step 1
                    Dim appData As COMSVCSLib.appData
                    appData = Marshal.PtrToStructure(New IntPtr(aAppData.ToInt32 + System.Convert.ToInt32((appIndex * appDataSize))), GetType(COMSVCSLib.appData))

                    'get the array of component instances for the current COM+ Application
                    Dim nClsIDCount As UInt32
                    Dim clsIDDataPtr As IntPtr
                    Dim gh1 As GCHandle = GCHandle.Alloc(clsIDDataPtr, GCHandleType.Pinned)
                    Dim AddrOfClsIDDataPtr As IntPtr = gh1.AddrOfPinnedObject

                    getAppData.GetAppData(appData.m_idApp, nClsIDCount, AddrOfClsIDDataPtr)
                    If nClsIDCount = 0 Then Return 0
                    clsIDDataPtr = New IntPtr(Marshal.ReadInt32(AddrOfClsIDDataPtr))

                    Dim clsIDDataSize As Integer
                    clsIDDataSize = Marshal.SizeOf(GetType(COMSVCSLib.CLSIDDATA))

                    Dim clsIDIndex As Integer
                    For clsIDIndex = 0 To System.Convert.ToInt64(nClsIDCount) - 1 Step 1
                        Dim clsIDData As COMSVCSLib.CLSIDDATA
                        clsIDData = Marshal.PtrToStructure(New IntPtr(clsIDDataPtr.ToInt64 + (clsIDIndex * clsIDDataSize)), GetType(COMSVCSLib.CLSIDDATA))
                        If UCase("{" & clsIDData.m_clsid.ToString & "}") = UCase(sComponentGUID) Then
                            bComponentFound = True
                            Console.WriteLine(".........Component Statistics")
                            'Console.WriteLine("............Name: " & vbTab 
                            & GetComponentNameByCLSID(clsIDData.m_clsid.ToString()))
                            'Console.WriteLine("............progID>" & vbTab 
                            & clsIDData.m_clsid.ToString())
                            Console.WriteLine("............bound>" & vbTab & 
                            clsIDData.m_cBound.ToString())
                            Console.WriteLine("............inCall>" & vbTab 
                            & clsIDData.m_cInCall.ToString())
                            Console.WriteLine("............pooled>" & vbTab 
                            & clsIDData.m_cPooled.ToString())
                            Console.WriteLine("............references>" & 
                            vbTab & clsIDData.m_cReferences.ToString())
                            Console.WriteLine("............responseTime>" & 
                            vbTab & System.Convert.ToInt64(clsIDData.m_dwRespTime))
                            Console.WriteLine("............callsCompleted>" 
                            & vbTab & clsIDData.m_cCallsCompleted.ToString())
                            Console.WriteLine("............callsFailed>" & 
                            vbTab & clsIDData.m_cCallsFailed.ToString())
                        End If
                        If bComponentFound Then Exit For
                    Next    'COM+ Component

                    Marshal.FreeCoTaskMem(clsIDDataPtr)
                    gh1.Free()
                    If bComponentFound Then Exit For
                Next    'COM+ Application

                Marshal.FreeCoTaskMem(aAppData)
                Marshal.ReleaseComObject(getAppData)
                gh.Free()

                Return 1
            Catch f As Exception
                Throw f
                'ErrorHandler(f)
                Return 0
            End Try
        End Function

