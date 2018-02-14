SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
--  Table structure for `dnslogs`
-- ----------------------------
DROP TABLE IF EXISTS `dnslogs`;
CREATE TABLE `dnslogs` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `domain` varchar(100) DEFAULT NULL,
  `domain_ip` text DEFAULT NULL,
  `port` VARCHAR(10) DEFAULT NULL,
  `dns_client_ip` varchar(30) DEFAULT NULL,
  `dns_server_ip` varchar(30) DEFAULT NULL,
  `record_time` varchar(30) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;

SET FOREIGN_KEY_CHECKS = 1;