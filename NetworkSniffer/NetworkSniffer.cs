using System;
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
        
       
        private bool ContinueCapturing = false;
        private delegate void AddTreeNode(TreeNode node);
        private TreeFactory treeFactory = new TreeFactory();
        private SocketManager socketManager = new SocketManager();

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
            cbIpAddressList.SelectedIndex = 1;

        }

        private void btnStartCapture_Click(object sender, EventArgs e)
        {
            if (cbIpAddressList.Text == "")
            {
                MessageBox.Show("Select an interface to capture the packets.", "Network Sniffer", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            try
            {
                if (!ContinueCapturing)
                {
                    btnStartCapture.Text = "&Stop";
                    ContinueCapturing = true;
                  
                        socketManager.Start(cbIpAddressList.Text);
                        ParseData();
                    
                }
                else
                {
                    btnStartCapture.Text = "&Start";
                    ContinueCapturing = false;
                    socketManager.Stop();
                    
                }
            }
            catch (ObjectDisposedException) { }
            catch (Exception exception)
            {
           //     MessageBox.Show(exception.Message, "Network Sniffer 1", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            

        }

        

        public void ParseData()
        {
            TreeNode rootNode = new TreeNode();
            TreeNode ipNode = treeFactory.MakeIPTreeNode(socketManager.headers.ip);
            rootNode.Nodes.Add(ipNode);

            switch (socketManager.headers.ip.ProtocolType)
            {
                case Protocol.TCP:
                    TcpHeader tcpHeader = new TcpHeader(socketManager.headers.ip.Data, socketManager.headers.ip.MessageLength);
                    TreeNode tcpNode = treeFactory.MakeTCPTreeNode(tcpHeader);
                    rootNode.Nodes.Add(tcpNode);
                    break;
                case Protocol.UDP:
                    UdpHeader udpHeader = new UdpHeader(socketManager.headers.ip.Data, (int)socketManager.headers.ip.MessageLength);
                    TreeNode udpNode = treeFactory.MakeUDPTreeNode(udpHeader);
                    rootNode.Nodes.Add(udpNode);
                    break;
                case Protocol.Unknown:
                    break;
            }
            AddTreeNode addTreeNode = new AddTreeNode(OnAddTreeNode);
            rootNode.Text = socketManager.headers.ip.SourceAddress.ToString() + "-" +
            socketManager.headers.ip.DestinationAddress.ToString();
            treeView.Invoke(addTreeNode, new object[] { rootNode });
        }

        public void OnAddTreeNode(TreeNode node)
        {
            treeView.Nodes.Add(node);
        }

        private void NetworkSnifferForm_FormClosing(object sender, FormClosingEventArgs e)
        {
          
             socketManager.Close();
         
        }
    }
}