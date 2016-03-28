﻿using System;
using System.Linq;
using System.Windows.Forms;
using System.Net;
using System.Net.Sockets;

namespace NetworkSniffer
{

    public enum Protocol
    {
        TCP = 6,
        UDP = 17,
        Unknown = -1
    };

    public partial class NetworkSnifferForm : Form
    {
        private Socket MainSocket;
        private byte[] ByteData = new byte[4096];
        private bool ContinueCapturing = false;
        private delegate void AddTreeNode(TreeNode node);

        public NetworkSnifferForm()
        {
            InitializeComponent();
        }

        private void NetworkSnifferForm_Load(object sender, EventArgs e)
        {
            IPHostEntry iPHostEntry = Dns.GetHostEntry(Dns.GetHostName());
            if (iPHostEntry.AddressList.Length > 0)
            {
                cbIpAddressList.DataSource = iPHostEntry.AddressList.Where(
                    ipa => ipa.AddressFamily == AddressFamily.InterNetwork).
                    Select(ip => ip.ToString()).ToList();
            }
        }

        private void btnStartCapture_Click(object sender, EventArgs e)
        {
            if (cbIpAddressList.Text == "")
            {
                MessageBox.Show("Select an interface to capture the packets.",
                    "Network Sniffer", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            try
            {
                if (!ContinueCapturing)
                {
                    btnStartCapture.Text = "&Stop";
                    ContinueCapturing = true;
                    MainSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
                    MainSocket.Bind(new IPEndPoint(IPAddress.Parse(cbIpAddressList.Text), 0));

                    MainSocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
                    byte[] byTrue = new byte[4] { 1, 0, 0, 0 };
                    byte[] byOut = new byte[4] { 1, 0, 0, 0 };
                    MainSocket.IOControl(IOControlCode.ReceiveAll, byTrue, byOut);
                    MainSocket.BeginReceive(ByteData, 0, ByteData.Length, SocketFlags.None,
                                            new AsyncCallback(OnReceive), null);
                }
                else
                {
                    btnStartCapture.Text = "&Start";
                    ContinueCapturing = false;
                    if (MainSocket != null)
                    {
                        MainSocket.Dispose();
                    }
                }
            }
            catch (ObjectDisposedException) { }
            catch (Exception exception)
            {
                MessageBox.Show(exception.Message, "Network Sniffer",
                                MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void OnReceive(IAsyncResult asyncResult)
        {
            try
            {
                int nReceived = MainSocket.EndReceive(asyncResult);
                ParseData(ByteData, nReceived);
                if (ContinueCapturing)
                {
                    ByteData = new byte[4096];
                    MainSocket.BeginReceive(ByteData, 0, ByteData.Length, SocketFlags.None, new AsyncCallback(OnReceive), null);
                }
            }
            catch (ObjectDisposedException) { }
            catch (Exception exception)
            {
                MessageBox.Show(exception.Message, "Network Sniffer",
                                MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void ParseData(byte[] byteData, int nReceived)
        {
            TreeNode rootNode = new TreeNode();
            IpHeader ipHeader = new IpHeader(byteData, nReceived);
            TreeNode ipNode = MakeIPTreeNode(ipHeader);
            rootNode.Nodes.Add(ipNode);

            switch (ipHeader.ProtocolType)
            {
                case Protocol.TCP: TcpHeader tcpHeader = new TcpHeader(ipHeader.Data, ipHeader.MessageLength);
                    TreeNode tcpNode = MakeTCPTreeNode(tcpHeader);
                    rootNode.Nodes.Add(tcpNode);
                    if (tcpHeader.DestinationPort == "53" || 
                        tcpHeader.SourcePort == "53")
                    {
                        TreeNode dnsNode = MakeDNSTreeNode(tcpHeader.Data,
                                            (int)tcpHeader.MessageLength);
                        rootNode.Nodes.Add(dnsNode);
                    }
                    break;
                case Protocol.UDP: UdpHeader udpHeader = new UdpHeader(ipHeader.Data, (int)ipHeader.MessageLength);
                    TreeNode udpNode = MakeUDPTreeNode(udpHeader);
                    rootNode.Nodes.Add(udpNode);
                    if (udpHeader.DestinationPort == "53" || 
                        udpHeader.SourcePort == "53")
                    {
                        TreeNode dnsNode = MakeDNSTreeNode(udpHeader.Data,
                                            Convert.ToInt32(udpHeader.Length) - 8);
                        rootNode.Nodes.Add(dnsNode);
                    }
                    break;
                case Protocol.Unknown:
                    break;
            }

            AddTreeNode addTreeNode = new AddTreeNode(OnAddTreeNode);
            rootNode.Text = ipHeader.SourceAddress.ToString() + "-" +
            ipHeader.DestinationAddress.ToString();
            treeView.Invoke(addTreeNode, new object[] { rootNode });
        }

        private TreeNode MakeIPTreeNode(IpHeader ipHeader)
        {
            TreeNode ipNode = new TreeNode();
            ipNode.Text = "IP";
            ipNode.Nodes.Add("Ver: " + ipHeader.Version);
            ipNode.Nodes.Add("Header Length: " + ipHeader.HeaderLength);
            ipNode.Nodes.Add("Differentiated Services: " +
                            ipHeader.DifferentiatedServices);
            ipNode.Nodes.Add("Total Length: " + ipHeader.TotalLength);
            ipNode.Nodes.Add("Identification: " + ipHeader.Identification);
            ipNode.Nodes.Add("Flags: " + ipHeader.Flags);
            ipNode.Nodes.Add("Fragmentation Offset: " + ipHeader.FragmentationOffset);
            ipNode.Nodes.Add("Time to live: " + ipHeader.TTL);
            switch (ipHeader.ProtocolType)
            {
                case Protocol.TCP:
                    ipNode.Nodes.Add("Protocol: " + "TCP");
                    break;
                case Protocol.UDP:
                    ipNode.Nodes.Add("Protocol: " + "UDP");
                    break;
                case Protocol.Unknown:
                    ipNode.Nodes.Add("Protocol: " + "Unknown");
                    break;
            }
            ipNode.Nodes.Add("Checksum: " + ipHeader.Checksum);
            ipNode.Nodes.Add("Source: " + ipHeader.SourceAddress.ToString());
            ipNode.Nodes.Add("Destination: " + ipHeader.DestinationAddress.ToString());
            return ipNode;
        }

        private TreeNode MakeTCPTreeNode(TcpHeader tcpHeader)
        {
            TreeNode tcpNode = new TreeNode();
            tcpNode.Text = "TCP";
            tcpNode.Nodes.Add("Source Port: " + tcpHeader.SourcePort);
            tcpNode.Nodes.Add("Destination Port: " + tcpHeader.DestinationPort);
            tcpNode.Nodes.Add("Sequence Number: " + tcpHeader.SequenceNumber);
            if (tcpHeader.AcknowledgementNumber != "")
            {
                tcpNode.Nodes.Add("Acknowledgement Number: " +
                                tcpHeader.AcknowledgementNumber);
            }
            tcpNode.Nodes.Add("Header Length: " + tcpHeader.HeaderLength);
            tcpNode.Nodes.Add("Flags: " + tcpHeader.Flags);
            tcpNode.Nodes.Add("Window Size: " + tcpHeader.WindowSize);
            tcpNode.Nodes.Add("Checksum: " + tcpHeader.Checksum);
            if (tcpHeader.UrgentPointer != "")
            {
                tcpNode.Nodes.Add("Urgent Pointer: " + tcpHeader.UrgentPointer);
            }
            return tcpNode;
        }

        private TreeNode MakeUDPTreeNode(UdpHeader udpHeader)
        {
            TreeNode udpNode = new TreeNode();
            udpNode.Text = "UDP";
            udpNode.Nodes.Add("Source Port: " + udpHeader.SourcePort);
            udpNode.Nodes.Add("Destination Port: " + udpHeader.DestinationPort);
            udpNode.Nodes.Add("Length: " + udpHeader.Length);
            udpNode.Nodes.Add("Checksum: " + udpHeader.Checksum);
            return udpNode;
        }

        private TreeNode MakeDNSTreeNode(byte[] byteData, int nLength)
        {
            DnsHeader dnsHeader = new DnsHeader(byteData, nLength);
            TreeNode dnsNode = new TreeNode();
            dnsNode.Text = "DNS";
            dnsNode.Nodes.Add("Identification: " + dnsHeader.Identification);
            dnsNode.Nodes.Add("Flags: " + dnsHeader.Flags);
            dnsNode.Nodes.Add("Questions: " + dnsHeader.TotalQuestions);
            dnsNode.Nodes.Add("Answer RRs: " + dnsHeader.TotalAnswerRRs);
            dnsNode.Nodes.Add("Authority RRs: " + dnsHeader.TotalAuthorityRRs);
            dnsNode.Nodes.Add("Additional RRs: " + dnsHeader.TotalAdditionalRRs);
            return dnsNode;
        }

        private void OnAddTreeNode(TreeNode node)
        {
            treeView.Nodes.Add(node);
        }

        private void NetworkSnifferForm_FormClosing(object sender, 
                                                    FormClosingEventArgs e)
        {
            if (ContinueCapturing && MainSocket != null)
            {
                MainSocket.Close();
            }
        }
    }
}