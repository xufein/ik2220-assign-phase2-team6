// define counter
counter_in, counter_drop, counter_out :: AverageCounter;

out1 :: Queue -> ToDevice(ids10-eth1); // connect sw2
out2 :: Queue -> counter_drop -> ToDevice(ids10-eth2); // connect insp
out3 :: Queue -> counter_out -> ToDevice(ids10-eth3); // connect lb2

in1 :: FromDevice(ids10-eth1, METHOD LINUX, SNIFFER false);
in3 :: FromDevice(ids10-eth3, METHOD LINUX, SNIFFER false);

classifier :: Classifier(
	// sql			 
	209/636174202f6574632f706173737764, // password
	209/636174202f7661722f6c6f672f, //log
	208/494E53455254, //insert
	208/555044415445, //update
	208/44454C455445, //delete
	// HTTP
	66/474554, //get
	66/48454144, //head
	66/5452414345, // trace
	66/4f5054494f4e53, //option
	66/44454c455445, //delete
	66/434f4e4e454354, //connect
	// rest
	-); 

in1 -> counter_in -> classifier;
// send to ids
classifier[0],classifier[1],classifier[2],classifier[3],classifier[4],classifier[5],classifier[6],classifier[7],classifier[8],classifier[9],classifier[10] -> out2;
// send to web server
classifier[11] -> out3;

in3 -> out1;

// report
DriverManager(wait , print > ../results/ids.report  "
	=================== IDS Report ===================
	Input Packet Rate (pps): $(counter_in.rate)
	Output Packet Rate(pps): $(counter_out.rate)

	Total # of input packets: $(counter_in.count)

	Total # of output packets: $(counter_out.count)

	Total # of dropped packets: $(counter_drop.count)
	==================================================
" , stop);

