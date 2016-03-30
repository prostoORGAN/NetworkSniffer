using System.Windows.Forms;

namespace NetworkSniffer
{
    public class TreeFactory
    {
    
       

        public TreeNode MakeIPTreeNode(IpHeader ipHeader)
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

        public TreeNode MakeTCPTreeNode(TcpHeader tcpHeader)
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

        public TreeNode MakeUDPTreeNode(UdpHeader udpHeader)
        {
            TreeNode udpNode = new TreeNode();
            udpNode.Text = "UDP";
            udpNode.Nodes.Add("Source Port: " + udpHeader.SourcePort);
            udpNode.Nodes.Add("Destination Port: " + udpHeader.DestinationPort);
            udpNode.Nodes.Add("Length: " + udpHeader.Length);
            udpNode.Nodes.Add("Checksum: " + udpHeader.Checksum);
            return udpNode;
        }

        
    }
}
