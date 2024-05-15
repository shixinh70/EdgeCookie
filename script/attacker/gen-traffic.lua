local mg     = require "moongen"
local memory = require "memory"
local device = require "device"
local stats  = require "stats"
local log    = require "log"

local ETH_SRC = "3c:fd:fe:04:c3:c2"
local ETH_DST = "3c:fd:fe:04:b1:c2"

function configure(parser)
	parser:description("Generates traffic.")
	parser:argument("txDev", "Device to transmit from."):convert(tonumber)
	parser:argument("rxDev", "Device to receive from."):convert(tonumber)
	parser:option("-r --rate", "Transmit rate in Mbit/s."):default(0):convert(tonumber)
	parser:option("-p --packet-rate", "Transmit rate in Mpps."):default(0):convert(tonumber)
	parser:option("-s --size", "Packet size (incl. CRC)."):default(70):convert(tonumber)
	parser:option("-t --time", "Run time of the test."):default(60):convert(tonumber)
	parser:option("-o --output", "Output file.")
	parser:option("-c --core", "Number of cores."):default(1):convert(tonumber)
	parser:option("-f --flows", "Number of flows (different src addr)"):default(1):convert(tonumber)
    parser:option("-a --ack-flood", "Start ack flood mode"):default(0):convert(tonumber)
    parser:option("-b --incr-ts", "Incremental timestamp"):default(0):convert(tonumber)
end

function master(args)
	txDev = device.config({port = args.txDev, txQueues = args.core})
	if rxDev ~= txDev then
		rxDev = device.config({port = args.rxDev, rxQueues = 1})
	else
		rxDev = txDev
	end
	device.waitForLinks()

	if args.packet_rate > 0 then
		args.rate = args.packet_rate * (args.size - 4) * 8
	end 

	if args.rate > 0 then
		txDev.totalRate = nil
		for i=0,args.core-1 do
			txDev:getTxQueue(i):setRate(args.rate / args.core)
		end
	end

	for i=0,args.core-1 do
		mg.startTask("loadSlave", txDev:getTxQueue(i), args.size - 4,
		             args.flows, i, args.ack_flood, args.incr_ts)
	end

	mg.setRuntime(args.time)

	local txCtr = stats:newDevTxCounter(txDev)
	local rxCtr = stats:newDevRxCounter(rxDev)
	
	while mg.running() do
		txCtr:update()
		rxCtr:update()

		mg.sleepMillisIdle(10)
	end

	txCtr:finalize()
	rxCtr:finalize()

	local txMpps, tmp1, tmp2, txPkts = txCtr:getStats()
	local rxMpps, tmp1, tmp2, rxPkts = rxCtr:getStats()

	log:info("RESULTS:")
	log:info("TX %.02f Mpps, %d pkts", txMpps.avg, txPkts)
	log:info("RX %.02f Mpps, %d pkts", rxMpps.avg, rxPkts)
	log:info("LOSS %.02f%%", (txPkts - rxPkts) / txPkts * 100)

	if args.output then
		file = io.open(args.output , "w")
		file:write("tx-mpps;tx-pkts;rx-mpps;rx-pkts\n")
		file:write(string.format("%.02f;%d;%.02f;%d\n", txMpps.avg, txPkts,
		                         rxMpps.avg, rxPkts))
		file:close()
	end
end

function loadSlave(txQueue, size, flows, seed, ack_flood, incr_ts)
	math.randomseed(seed)
	minIp = parseIPAddress("10.0.0.0")
    mints = 1
	local mem = memory.createMemPool(function(buf)
		buf:getTcpPacket():fill{ 
			ethSrc = ETH_SRC,
			ethDst = ETH_DST,
			ip4Src = "10.20.0.3",
			ip4Dst = "10.20.0.2",
			tcpDst = 80,
			tcpSyn = 1,
			tcpSeqNumber = 1,
			tcpWindow = 10,
			pktLength = size,
            tcpDataOffset = 8

		}
        if ack_flood == 1 then
            buf:getTcpPacket():fill{
                ethSrc = ETH_SRC,
                ethDst = ETH_DST,
                ip4Src = "10.20.0.3",
                ip4Dst = "10.20.0.2",
                tcpDst = 80,
                tcpAck = 1,
                tcpSeqNumber = 1,
                tcpWindow = 10,
                pktLength = size,
                tcpDataOffset = 8
            }
        end
	end)

	local bufs = mem:bufArray()
    local tscounter = 1
	while mg.running() do
		bufs:alloc(size)

		for i, buf in ipairs(bufs) do
			local pkt = buf:getTcpPacket()
            
            if flows > 1 then
                srcIp = minIp
                offset = math.random(0, flows - 1)
                pkt.ip4.src:set(srcIp + offset)
            end
            pkt.tcp:setNopOption(0)
            pkt.tcp:setNopOption(1)
            pkt.tcp:setTSOption(2,1234,min_ts)
            if incr_ts == 1 then
                pkt.tcp:setTSOption(2,1234,(min_ts + tscounter) % 0xffffffff)
                tscounter = incAndWrap(tscounter, 2^32)
            end

		end

		bufs:offloadTcpChecksums()
		txQueue:send(bufs)
	end
end