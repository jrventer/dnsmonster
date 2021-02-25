CREATE TABLE IF NOT EXISTS DNS_LOG (
  DnsDate Date,
  timestamp DateTime,
  Server String,
  NodeQualifier UInt8,
  ClusterName FixedString(64),
  IPVersion UInt8,
  SrcIP UInt32,
  DstIP UInt32,
  Protocol FixedString(3),
  QR UInt8,
  OpCode UInt8,
  Class UInt16,
  Type UInt16,
  Edns0Present UInt8,
  DoBit UInt8,
  FullQuery String,
  ResponseCode UInt8,
  Question String,
  EtldPlusOne String,
  Size UInt16,
  ID UUID
) 
  ENGINE = MergeTree()
  PARTITION BY toYYYYMMDD(DnsDate)
  PRIMARY KEY (timestamp , ClusterName, Server, NodeQualifier, cityHash64(ID))
  ORDER BY (timestamp, ClusterName, Server, NodeQualifier, cityHash64(ID))
  SAMPLE BY cityHash64(ID)
  TTL DnsDate + INTERVAL 30 DAY -- DNS_TTL_VARIABLE
  SETTINGS index_granularity = 8192;

-- View 1min DNS Metrics per Cluster, Server Subscriber/Internet Request/Response
CREATE MATERIALIZED VIEW IF NOT EXISTS DNS_METRICS_1M
  ENGINE=SummingMergeTree()
  PARTITION BY toYYYYMM(DnsDate)
  PRIMARY KEY (DnsDate, timestamp , ClusterName, Server, NodeQualifier, QR)
  ORDER BY (DnsDate, timestamp, ClusterName, Server, NodeQualifier, QR)
  TTL DnsDate + INTERVAL 30 DAY -- DNS_TTL_VARIABLE
  SETTINGS index_granularity = 8192
  AS
  SELECT DnsDate, toStartOfMinute(timestamp) as timestamp, ClusterName, Server, NodeQualifier, QR,
  count(*) as Total, countIf(Protocol='udp') as udp, countIf(Protocol='tcp') as tcp, countIf(DoBit=1) as DoBit, countIf(Edns0Present=1) as Edns0,
  countIf(IPVersion=4) as ipV4,countIf(IPVersion=6) as ipV6 
  FROM DNS_LOG
  GROUP BY DnsDate, timestamp, ClusterName, Server, NodeQualifier, QR;

-- View for top queried Top Level + 1 domains
 CREATE MATERIALIZED VIEW IF NOT EXISTS DNS_ETLDPLUSONE_1M
  ENGINE=SummingMergeTree()
  PARTITION BY toYYYYMMDD(DnsDate)
  PRIMARY KEY (DnsDate, timestamp , ClusterName, Server, NodeQualifier)
  ORDER BY (DnsDate, timestamp, ClusterName, Server, NodeQualifier, EtldPlusOne)
  TTL DnsDate + INTERVAL 30 DAY -- DNS_TTL_VARIABLE
  SETTINGS index_granularity = 8192
  AS
  SELECT DnsDate, toStartOfMinute(timestamp) as timestamp, ClusterName, Server, NodeQualifier, EtldPlusOne, count(*) as Requests, sum(Size) as TotalRequestBytes 
  FROM DNS_LOG 
  WHERE QR=0 
  GROUP BY DnsDate, timestamp, ClusterName, Server, NodeQualifier, EtldPlusOne;

-- View for top queried domains
 CREATE MATERIALIZED VIEW IF NOT EXISTS DNS_DOMAIN_1M
  ENGINE=SummingMergeTree()
  PARTITION BY toYYYYMMDD(DnsDate)
  PRIMARY KEY (DnsDate, timestamp , ClusterName, Server, NodeQualifier)
  ORDER BY (DnsDate, timestamp, ClusterName, Server, NodeQualifier, Question)
  TTL DnsDate + INTERVAL 30 DAY -- DNS_TTL_VARIABLE
  SETTINGS index_granularity = 8192
  AS
  SELECT DnsDate, toStartOfMinute(timestamp) as timestamp, ClusterName, Server, NodeQualifier, Question, count(*) as Requests, sum(Size) as TotalRequestBytes 
  FROM DNS_LOG 
  WHERE QR=0 
  GROUP BY DnsDate, timestamp, ClusterName, Server, NodeQualifier, Question;

  -- View for unique domain count
 CREATE MATERIALIZED VIEW IF NOT EXISTS DNS_DOMAIN_UNIQ_1M
  ENGINE=AggregatingMergeTree()
  PARTITION BY toYYYYMMDD(DnsDate)
  PRIMARY KEY (DnsDate, timestamp , ClusterName, Server, NodeQualifier)
  ORDER BY (DnsDate, timestamp, ClusterName, Server, NodeQualifier)
  TTL DnsDate + INTERVAL 30 DAY -- DNS_TTL_VARIABLE
  SETTINGS index_granularity = 8192
  AS
  SELECT DnsDate, toStartOfMinute(timestamp) as timestamp, ClusterName, Server, NodeQualifier, uniqState(Question) AS UniqueDnsCount  
  FROM DNS_LOG 
  WHERE QR=0 
  GROUP BY DnsDate, timestamp, ClusterName, Server, NodeQualifier;

-- View wih query OpCode
CREATE MATERIALIZED VIEW IF NOT EXISTS DNS_OPCODE_1M
  ENGINE=SummingMergeTree()
  PARTITION BY toYYYYMM(DnsDate)
  PRIMARY KEY (DnsDate, timestamp , ClusterName, Server, NodeQualifier, QR, OpCode)
  ORDER BY (DnsDate, timestamp, ClusterName, Server, NodeQualifier, QR, OpCode)
  TTL DnsDate + INTERVAL 30 DAY -- DNS_TTL_VARIABLE
  SETTINGS index_granularity = 8192
  AS
  SELECT DnsDate, toStartOfMinute(timestamp) as timestamp, ClusterName, Server, NodeQualifier, QR, OpCode,
  count(*) as Total
  FROM DNS_LOG
  GROUP BY DnsDate, timestamp, ClusterName, Server, NodeQualifier, QR, OpCode;

-- View with Query Class
CREATE MATERIALIZED VIEW IF NOT EXISTS DNS_CLASS_1M
  ENGINE=SummingMergeTree()
  PARTITION BY toYYYYMM(DnsDate)
  PRIMARY KEY (DnsDate, timestamp , ClusterName, Server, NodeQualifier, Class)
  ORDER BY (DnsDate, timestamp, ClusterName, Server, NodeQualifier, Class)
  TTL DnsDate + INTERVAL 30 DAY -- DNS_TTL_VARIABLE
  SETTINGS index_granularity = 8192
  AS
  SELECT DnsDate, toStartOfMinute(timestamp) as timestamp, ClusterName, Server, NodeQualifier, Class,
  count(*) as Total
  FROM DNS_LOG
  WHERE QR=0
  GROUP BY DnsDate, timestamp, ClusterName, Server, NodeQualifier, Class;

-- View with Query Types
CREATE MATERIALIZED VIEW IF NOT EXISTS DNS_TYPE_1M
  ENGINE=SummingMergeTree()
  PARTITION BY toYYYYMM(DnsDate)
  PRIMARY KEY (DnsDate, timestamp , ClusterName, Server, NodeQualifier, Type)
  ORDER BY (DnsDate, timestamp, ClusterName, Server, NodeQualifier, Type)
  TTL DnsDate + INTERVAL 30 DAY -- DNS_TTL_VARIABLE
  SETTINGS index_granularity = 8192
  AS
  SELECT DnsDate, toStartOfMinute(timestamp) as timestamp, ClusterName, Server, NodeQualifier, Type,
  count(*) as Total
  FROM DNS_LOG
  WHERE QR=0
  GROUP BY DnsDate, timestamp, ClusterName, Server, NodeQualifier, Type;

-- View with query responses
CREATE MATERIALIZED VIEW IF NOT EXISTS DNS_RESPONSECODE_1M
  ENGINE=SummingMergeTree()
  PARTITION BY toYYYYMM(DnsDate)
  PRIMARY KEY (DnsDate, timestamp , ClusterName, Server, NodeQualifier, ResponseCode)
  ORDER BY (DnsDate, timestamp, ClusterName, Server, NodeQualifier, ResponseCode)
  TTL DnsDate + INTERVAL 30 DAY -- DNS_TTL_VARIABLE
  SETTINGS index_granularity = 8192
  AS
  SELECT DnsDate, toStartOfMinute(timestamp) as timestamp, ClusterName, Server, NodeQualifier, ResponseCode,
  count(*) as Total
  FROM DNS_LOG
  WHERE QR=1
  GROUP BY DnsDate, timestamp, ClusterName, Server, NodeQualifier, ResponseCode;


-- View with packet sizes
CREATE MATERIALIZED VIEW IF NOT EXISTS DNS_PACKET_SIZES_1M
ENGINE=AggregatingMergeTree()
 PARTITION BY toYYYYMM(DnsDate)
 PRIMARY KEY (DnsDate, timestamp , ClusterName, Server, NodeQualifier, QR)
 ORDER BY (DnsDate, timestamp, ClusterName, Server, NodeQualifier, QR)
 TTL DnsDate + INTERVAL 6 MONTH -- DNS_TTL_VARIABLE
 SETTINGS index_granularity = 8192
 AS
 SELECT DnsDate, toStartOfMinute(timestamp) as timestamp, ClusterName, Server, NodeQualifier, QR, sumState(toUInt64(Size)) AS TotalSize, avgState(Size) AS AverageSize 
 FROM DNS_LOG
 GROUP BY DnsDate, timestamp, ClusterName, Server, NodeQualifier, QR;