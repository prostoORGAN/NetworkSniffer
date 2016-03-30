using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System;
using System.Linq;
using System.Windows.Forms;
using System.Net;
using System.Net.Sockets;

namespace NetworkSniffer
{
    class SocketManager
    {
       public struct Headers
        {
           public IpHeader ip;
           public TcpHeader tcpProtocol;
           public UdpHeader udpProtocol;
           public int ProtocolType;
        };

        public Headers headers;
        private byte[] ByteData = new byte[2048];
        private Socket MainSocket;
        private bool continueCapturing = false;
        public bool ContinueCapturing { get { return continueCapturing; } set { SetContinueCapturing(continueCapturing);  } }

        private void SetContinueCapturing(bool G)
        {
            continueCapturing = G;
           
        }

        public void Start(string HostName)
        {
            MainSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
            MainSocket.Bind(new IPEndPoint(IPAddress.Parse(HostName), 0));
            MainSocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
            byte[] byTrue = new byte[4] { 1, 0, 0, 0 };
            byte[] byOut = new byte[4] { 1, 0, 0, 0 };
            MainSocket.IOControl(IOControlCode.ReceiveAll, byTrue, byOut);


            MainSocket.BeginReceive(ByteData, 0, ByteData.Length, SocketFlags.None, new AsyncCallback(OnReceive), null);
            
        }

        public void Stop()
        {
            if (MainSocket != null)
            {
                MainSocket.Dispose();
                MainSocket.Close();
            }
        }

        public void Close()
        {
            if (ContinueCapturing && MainSocket != null)
            {
               // MainSocket.Close();
            }
        }

        private void OnReceive(IAsyncResult asyncResult)
        {
            try
            {
                int nReceived = MainSocket.EndReceive(asyncResult);

                IpHeader ipHeader = new IpHeader(ByteData, nReceived);
                headers.ip = ipHeader;
                switch (ipHeader.ProtocolType)
                {
                    case Protocol.TCP:
                        TcpHeader tcpHeader = new TcpHeader(ipHeader.Data, ipHeader.MessageLength);
                        headers.tcpProtocol = tcpHeader;
                        headers.ProtocolType = 1;
                        break;
                    case Protocol.UDP:
                        UdpHeader udpHeader = new UdpHeader(ipHeader.Data, (int)ipHeader.MessageLength);
                        headers.udpProtocol = udpHeader;
                        headers.ProtocolType = 0;
                        break;
                    case Protocol.Unknown:
                        headers.ProtocolType = -1;
                        break;
                }
                
             
                //ParseData(ByteData, nReceived);
              /*  if (ContinueCapturing)
                {
                    ByteData = new byte[2048];
                    MainSocket.BeginReceive(ByteData, 0, ByteData.Length, SocketFlags.None, new AsyncCallback(OnReceive), null);
                }*/
            }
            catch (ObjectDisposedException) { }
            catch (Exception exception)
            {
                MessageBox.Show(exception.Message, "Network Sniffer", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }
}
