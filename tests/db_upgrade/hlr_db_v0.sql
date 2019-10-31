PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE subscriber (
-- OsmoHLR's DB scheme is modelled roughly after TS 23.008 version 13.3.0
	id		INTEGER PRIMARY KEY,
	-- Chapter 2.1.1.1
	imsi		VARCHAR(15) UNIQUE NOT NULL,
	-- Chapter 2.1.2
	msisdn		VARCHAR(15) UNIQUE,
	-- Chapter 2.2.3: Most recent / current IMEI
	imeisv		VARCHAR,
	-- Chapter 2.4.5
	vlr_number	VARCHAR(15),
	-- Chapter 2.4.6
	hlr_number	VARCHAR(15),
	-- Chapter 2.4.8.1
	sgsn_number	VARCHAR(15),
	-- Chapter 2.13.10
	sgsn_address	VARCHAR,
	-- Chapter 2.4.8.2
	ggsn_number	VARCHAR(15),
	-- Chapter 2.4.9.2
	gmlc_number	VARCHAR(15),
	-- Chapter 2.4.23
	smsc_number	VARCHAR(15),
	-- Chapter 2.4.24
	periodic_lu_tmr	INTEGER,
	-- Chapter 2.13.115
	periodic_rau_tau_tmr INTEGER,
	-- Chapter 2.1.1.2: network access mode
	nam_cs		BOOLEAN NOT NULL DEFAULT 1,
	nam_ps		BOOLEAN NOT NULL DEFAULT 1,
	-- Chapter 2.1.8
	lmsi		INTEGER,
	-- The below purged flags might not even be stored non-volatile,
	-- refer to TS 23.012 Chapter 3.6.1.4
	-- Chapter 2.7.5
	ms_purged_cs	BOOLEAN NOT NULL DEFAULT 0,
	-- Chapter 2.7.6
	ms_purged_ps	BOOLEAN NOT NULL DEFAULT 0
);
INSERT INTO subscriber VALUES(1,'123456789012345','098765432109876',NULL,'MSC-1',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,1,1,NULL,0,0);
INSERT INTO subscriber VALUES(2,'111111111',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,1,1,NULL,1,0);
INSERT INTO subscriber VALUES(3,'222222222','22222',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,1,1,NULL,0,1);
INSERT INTO subscriber VALUES(4,'333333','3',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,1,NULL,0,0);
INSERT INTO subscriber VALUES(5,'444444444444444','4444',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,1,0,NULL,0,0);
INSERT INTO subscriber VALUES(6,'5555555','55555555555555',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,0,NULL,0,0);
CREATE TABLE subscriber_apn (
	subscriber_id	INTEGER,		-- subscriber.id
	apn		VARCHAR(256) NOT NULL
);
CREATE TABLE subscriber_multi_msisdn (
-- Chapter 2.1.3
	subscriber_id	INTEGER,		-- subscriber.id
	msisdn		VARCHAR(15) NOT NULL
);
CREATE TABLE auc_2g (
	subscriber_id	INTEGER PRIMARY KEY,	-- subscriber.id
	algo_id_2g	INTEGER NOT NULL,	-- enum osmo_auth_algo value
	ki		VARCHAR(32) NOT NULL	-- hex string: subscriber's secret key (128bit)
);
INSERT INTO auc_2g VALUES(1,1,'BeefedCafeFaceAcedAddedDecadeFee');
INSERT INTO auc_2g VALUES(4,2,'33333333333333333333333333333333');
INSERT INTO auc_2g VALUES(6,4,'55555555555555555555555555555555');
CREATE TABLE auc_3g (
	subscriber_id	INTEGER PRIMARY KEY,	-- subscriber.id
	algo_id_3g	INTEGER NOT NULL,	-- enum osmo_auth_algo value
	k		VARCHAR(32) NOT NULL,	-- hex string: subscriber's secret key (128bit)
	op		VARCHAR(32),		-- hex string: operator's secret key (128bit)
	opc		VARCHAR(32),		-- hex string: derived from OP and K (128bit)
	sqn		INTEGER NOT NULL DEFAULT 0,	-- sequence number of key usage
	-- nr of index bits at lower SQN end
	ind_bitlen	INTEGER NOT NULL DEFAULT 5
);
INSERT INTO auc_3g VALUES(1,5,'C01ffedC1cadaeAc1d1f1edAcac1aB0a',NULL,'CededEffacedAceFacedBadFadedBeef',0,5);
INSERT INTO auc_3g VALUES(5,5,'44444444444444444444444444444444','44444444444444444444444444444444',NULL,0,5);
INSERT INTO auc_3g VALUES(6,5,'55555555555555555555555555555555',NULL,'55555555555555555555555555555555',0,5);
CREATE UNIQUE INDEX idx_subscr_imsi ON subscriber (imsi)
;
COMMIT;
