
CREATE TABLE subscriber_rat (
	subscriber_id	INTEGER,		-- subscriber.id
	rat		TEXT CHECK(rat in ('GERAN-A', 'UTRAN-Iu')) NOT NULL,	-- Radio Access Technology, see enum ran_type
	allowed		BOOLEAN NOT NULL DEFAULT 0,
);

PRAGMA user_version = 2;
