-- phpMyAdmin SQL Dump
-- version 4.0.10deb1
-- http://www.phpmyadmin.net
--
-- Host: localhost
-- Generation Time: Dec 11, 2016 at 01:43 PM
-- Server version: 5.5.53-0ubuntu0.14.04.1
-- PHP Version: 5.5.9-1ubuntu4.20

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;


--
-- Database: `sdp_test`
--
USE `sdp_test`;

-- --------------------------------------------------------

--
-- Table structure for table `closed_connection`
--

CREATE TABLE IF NOT EXISTS `closed_connection` (
  `gateway_sdpid` int(11) NOT NULL,
  `client_sdpid` int(11) NOT NULL,
  `service_id` int(11) NOT NULL,
  `start_timestamp` bigint(20) NOT NULL,
  `end_timestamp` bigint(20) NOT NULL,
  `protocol` tinytext COLLATE utf8_bin NOT NULL,
  `source_ip` tinytext COLLATE utf8_bin NOT NULL,
  `source_port` int(11) NOT NULL,
  `destination_ip` tinytext COLLATE utf8_bin NOT NULL,
  `destination_port` int(11) NOT NULL,
  `nat_destination_ip` tinytext COLLATE utf8_bin NOT NULL,
  `nat_destination_port` int(11) NOT NULL,
  PRIMARY KEY (`gateway_sdpid`,`client_sdpid`,`start_timestamp`,`source_port`),
  KEY `gateway_sdpid` (`gateway_sdpid`),
  KEY `client_sdpid` (`client_sdpid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

--
-- RELATIONS FOR TABLE `closed_connection`:
--   `gateway_sdpid`
--       `sdpid` -> `sdpid`
--   `client_sdpid`
--       `sdpid` -> `sdpid`
--

-- --------------------------------------------------------

--
-- Table structure for table `controller`
--

CREATE TABLE IF NOT EXISTS `controller` (
  `sdpid` int(11) NOT NULL,
  `name` varchar(1024) COLLATE utf8_bin NOT NULL,
  `address` varchar(4096) COLLATE utf8_bin NOT NULL COMMENT 'ip or url',
  `port` int(11) NOT NULL,
  `gateway_sdpid` int(11) DEFAULT NULL,
  `service_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`sdpid`),
  KEY `service_id` (`service_id`),
  KEY `gateway_sdpid` (`gateway_sdpid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

--
-- RELATIONS FOR TABLE `controller`:
--   `sdpid`
--       `sdpid` -> `sdpid`
--   `service_id`
--       `service` -> `id`
--   `gateway_sdpid`
--       `sdpid` -> `sdpid`
--

--
-- Dumping data for table `controller`
--

INSERT INTO `controller` (`sdpid`, `name`, `address`, `port`, `gateway_sdpid`, `service_id`) VALUES
(111, 'ctrl1', '127.0.0.1', 5000, 444, 1);

-- --------------------------------------------------------

--
-- Table structure for table `environment`
--

CREATE TABLE IF NOT EXISTS `environment` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(1024) COLLATE utf8_bin NOT NULL,
  `mobile` tinyint(1) NOT NULL,
  `os_group` enum('Android','iOS','Windows','OSX','Linux') COLLATE utf8_bin NOT NULL,
  `os_version` varchar(1024) COLLATE utf8_bin NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=1 ;

-- --------------------------------------------------------

--
-- Table structure for table `gateway`
--

CREATE TABLE IF NOT EXISTS `gateway` (
  `sdpid` int(11) NOT NULL,
  `name` varchar(1024) COLLATE utf8_bin NOT NULL,
  `address` varchar(1024) COLLATE utf8_bin NOT NULL COMMENT 'ip or url',
  `port` int(11) DEFAULT NULL,
  PRIMARY KEY (`sdpid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

--
-- RELATIONS FOR TABLE `gateway`:
--   `sdpid`
--       `sdpid` -> `sdpid`
--

--
-- Dumping data for table `gateway`
--

INSERT INTO `gateway` (`sdpid`, `name`, `address`, `port`) VALUES
(222, 'gate2', '127.0.0.1', NULL),
(444, 'gate3', '192.168.1.36', NULL);

-- --------------------------------------------------------

--
-- Table structure for table `gateway_controller`
--

CREATE TABLE IF NOT EXISTS `gateway_controller` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `gateway_sdpid` int(11) NOT NULL,
  `controller_sdpid` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `gateway_sdpid` (`gateway_sdpid`),
  KEY `controller_sdpid` (`controller_sdpid`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=3 ;

--
-- RELATIONS FOR TABLE `gateway_controller`:
--   `gateway_sdpid`
--       `sdpid` -> `sdpid`
--   `controller_sdpid`
--       `sdpid` -> `sdpid`
--

--
-- Dumping data for table `gateway_controller`
--

INSERT INTO `gateway_controller` (`id`, `gateway_sdpid`, `controller_sdpid`) VALUES
(1, 222, 111),
(2, 444, 111);

-- --------------------------------------------------------

--
-- Table structure for table `group`
--

CREATE TABLE IF NOT EXISTS `group` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `valid` tinyint(4) NOT NULL DEFAULT '1',
  `name` varchar(1024) COLLATE utf8_bin NOT NULL,
  `Description` varchar(4096) COLLATE utf8_bin NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=2 ;

--
-- Triggers `group`
--
DROP TRIGGER IF EXISTS `group_after_delete`;
DELIMITER //
CREATE TRIGGER `group_after_delete` AFTER DELETE ON `group`
 FOR EACH ROW BEGIN
    INSERT INTO refresh_trigger
    SET table_name = 'group',
        event = 'delete';
END
//
DELIMITER ;

-- --------------------------------------------------------

--
-- Table structure for table `group_service`
--

CREATE TABLE IF NOT EXISTS `group_service` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `group_id` int(11) NOT NULL,
  `service_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `service_id` (`service_id`),
  KEY `group_id` (`group_id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=2 ;

--
-- RELATIONS FOR TABLE `group_service`:
--   `group_id`
--       `group` -> `id`
--   `service_id`
--       `service` -> `id`
--

--
-- Triggers `group_service`
--
DROP TRIGGER IF EXISTS `group_service_after_delete`;
DELIMITER //
CREATE TRIGGER `group_service_after_delete` AFTER DELETE ON `group_service`
 FOR EACH ROW BEGIN
    INSERT INTO refresh_trigger
    SET table_name = 'group_service',
        event = 'delete';
END
//
DELIMITER ;
DROP TRIGGER IF EXISTS `group_service_after_insert`;
DELIMITER //
CREATE TRIGGER `group_service_after_insert` AFTER INSERT ON `group_service`
 FOR EACH ROW BEGIN
    INSERT INTO refresh_trigger
    SET table_name = 'group_service',
        event = 'insert';
END
//
DELIMITER ;
DROP TRIGGER IF EXISTS `group_service_after_update`;
DELIMITER //
CREATE TRIGGER `group_service_after_update` AFTER UPDATE ON `group_service`
 FOR EACH ROW BEGIN
    INSERT INTO refresh_trigger
    SET table_name = 'group_service',
        event = 'update';
END
//
DELIMITER ;

-- --------------------------------------------------------

--
-- Table structure for table `open_connection`
--

CREATE TABLE IF NOT EXISTS `open_connection` (
  `gateway_sdpid` int(11) NOT NULL,
  `client_sdpid` int(11) NOT NULL,
  `service_id` int(11) NOT NULL,
  `start_timestamp` bigint(20) NOT NULL,
  `end_timestamp` bigint(20) NOT NULL,
  `protocol` tinytext COLLATE utf8_bin NOT NULL,
  `source_ip` tinytext COLLATE utf8_bin NOT NULL,
  `source_port` int(11) NOT NULL,
  `destination_ip` tinytext COLLATE utf8_bin NOT NULL,
  `destination_port` int(11) NOT NULL,
  `nat_destination_ip` tinytext COLLATE utf8_bin NOT NULL,
  `nat_destination_port` int(11) NOT NULL,
  `gateway_controller_connection_id` int(11) NOT NULL COMMENT 'Only used to track open conns, not an index to a table',
  PRIMARY KEY (`gateway_controller_connection_id`,`client_sdpid`,`start_timestamp`,`source_port`),
  KEY `gateway_sdpid` (`gateway_sdpid`),
  KEY `client_sdpid` (`client_sdpid`),
  KEY `service_id` (`service_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

--
-- RELATIONS FOR TABLE `open_connection`:
--   `gateway_sdpid`
--       `sdpid` -> `sdpid`
--   `client_sdpid`
--       `sdpid` -> `sdpid`
--   `service_id`
--       `service` -> `id`
--

-- --------------------------------------------------------

--
-- Table structure for table `refresh_trigger`
--

CREATE TABLE IF NOT EXISTS `refresh_trigger` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `table_name` tinytext COLLATE utf8_bin NOT NULL,
  `event` tinytext COLLATE utf8_bin NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=33 ;

-- --------------------------------------------------------

--
-- Table structure for table `sdpid`
--

CREATE TABLE IF NOT EXISTS `sdpid` (
  `sdpid` int(11) NOT NULL AUTO_INCREMENT,
  `valid` tinyint(1) NOT NULL DEFAULT '1',
  `type` enum('client','gateway','controller') COLLATE utf8_bin NOT NULL DEFAULT 'client',
  `country` varchar(128) COLLATE utf8_bin NOT NULL,
  `state` varchar(128) COLLATE utf8_bin NOT NULL,
  `locality` varchar(128) COLLATE utf8_bin NOT NULL,
  `org` varchar(128) COLLATE utf8_bin NOT NULL,
  `org_unit` varchar(128) COLLATE utf8_bin DEFAULT NULL,
  `alt_name` varchar(128) COLLATE utf8_bin DEFAULT NULL,
  `email` varchar(128) COLLATE utf8_bin DEFAULT NULL,
  `encrypt_key` varchar(2048) COLLATE utf8_bin DEFAULT NULL,
  `hmac_key` varchar(2048) COLLATE utf8_bin DEFAULT NULL,
  `serial` varchar(32) COLLATE utf8_bin NOT NULL,
  `last_cred_update` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `cred_update_due` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `user_id` int(11) DEFAULT NULL,
  `environment_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`sdpid`),
  KEY `user_id` (`user_id`),
  KEY `environment_id` (`environment_id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=55556 ;

--
-- RELATIONS FOR TABLE `sdpid`:
--   `user_id`
--       `user` -> `id`
--   `environment_id`
--       `environment` -> `id`
--

--
-- Dumping data for table `sdpid`
--

INSERT INTO `sdpid` (`sdpid`, `valid`, `type`, `country`, `state`, `locality`, `org`, `org_unit`, `alt_name`, `email`, `encrypt_key`, `hmac_key`, `serial`, `last_cred_update`, `cred_update_due`, `user_id`, `environment_id`) VALUES
(111, 1, 'controller', 'US', 'Virginia', 'Waterford', 'Waverley Labs, LLC', 'R&D', NULL, 'email@email.com', NULL, NULL, '0', '0000-00-00 00:00:00', '0000-00-00 00:00:00', NULL, NULL),
(333, 1, 'client', 'US', 'Virginia', 'Leesburg', 'Waverley Labs, LLC', 'R&D', NULL, 'email@email.com', 'Xpee90NZMvAyKJ5fxQIRALNdETK8w3pTR60NJBJy5Bw=', 'PRxnFcl+rUFpg2R6sHyuAiCs0imvVP1wn0Qweqokd9XZweOwmRABWtpxehbahY7QuMKhbE690ln5E6VtqQJBAIOEtHE+oqFe5kPL3oUGP+y+YvIFcr/iWYhmRJ+HHBRjiToNQIUO7n2xPehBlOseFYRT27XK0Cyn6BtHBCM21Wc=', '00AF8F8EAC509B9321', '2016-07-14 21:30:08', '2016-08-14 04:00:00', 1, NULL),
(222, 1, 'gateway', 'US', 'Virginia', 'Waterford', 'Waverley Labs, LLC', 'R&D', NULL, 'email@email.com', 'z8ngq6MaidxxStiUHk0CECm0CBSuYUvyD8zb99oliV4=', '60stItDmZeQNWz8ODvz1fdchhYp3h+finZieSO6vKUdSSUkPyglKVv9heFc23Yh7vbRp+jvX2eIN+rAa8QJBAOJ7GALaqWPbE/DUu+UIzLbJvNzvCPLj+iUe/td+ot6jVNGOMrIitsEt1r9gf66eGq6WZJ6lY60USIndz0NrdMA=', 'AF9F9DBA208EF44F', '2016-07-14 21:44:15', '2016-08-14 04:00:00', NULL, NULL),
(444, 1, 'gateway', 'US', 'Virginia', 'Leesburg', 'Waverley Labs, LLC', 'R&D', NULL, 'email@email.com', 'cRUukYanhaY7pcbS0QIRAOxuP4MfXB1YcLN1gWxEPD8=', 'wYnVbpwtCgfsxJb7zmRURPN1pw9OPKFBRP77pz8ILY2Ey4l5tqvPV8Q0dPGN5NkF6RMuYd7r5i+PmEEep/sCQC/ejhPAGPrrgLAc1/OAVYSTh6lLYx4N7vjJqSEnmhy/FQVAvNv2WWoOT0GCyNjWfoO16W2hFtC++1+5I8AIuy8=', '00AF8F8EAC509B9323', '2016-07-14 21:28:40', '2016-08-14 04:00:00', NULL, NULL),
(555, 1, 'client', 'US', 'Florida', 'Miami', 'Waverley Labs, LLC', 'R&D', NULL, 'email@email.com', 'someencryptkey', 'somehmackey', '00AF8F8EAC509B9324', '0000-00-00 00:00:00', '0000-00-00 00:00:00', 2, NULL);

--
-- Triggers `sdpid`
--
DROP TRIGGER IF EXISTS `sdpid_after_delete`;
DELIMITER //
CREATE TRIGGER `sdpid_after_delete` AFTER DELETE ON `sdpid`
 FOR EACH ROW BEGIN
    INSERT INTO refresh_trigger
    SET table_name = 'sdpid',
        event = 'delete';
END
//
DELIMITER ;
DROP TRIGGER IF EXISTS `sdpid_after_update`;
DELIMITER //
CREATE TRIGGER `sdpid_after_update` AFTER UPDATE ON `sdpid`
 FOR EACH ROW BEGIN
IF OLD.user_id != NEW.user_id OR
   OLD.valid != NEW.valid THEN
    INSERT INTO refresh_trigger
    SET table_name = 'sdpid',
        event = 'update';
END IF;
END
//
DELIMITER ;

-- --------------------------------------------------------

--
-- Table structure for table `sdpid_service`
--

CREATE TABLE IF NOT EXISTS `sdpid_service` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `sdpid` int(11) NOT NULL,
  `service_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `service_id` (`service_id`),
  KEY `sdpid` (`sdpid`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=11 ;

--
-- RELATIONS FOR TABLE `sdpid_service`:
--   `sdpid`
--       `sdpid` -> `sdpid`
--   `service_id`
--       `service` -> `id`
--

--
-- Dumping data for table `sdpid_service`
--

INSERT INTO `sdpid_service` (`id`, `sdpid`, `service_id`) VALUES
(1, 333, 1),
(2, 333, 3),
(3, 333, 4),
(4, 555, 2),
(5, 555, 1),
(6, 444, 1);

--
-- Triggers `sdpid_service`
--
DROP TRIGGER IF EXISTS `sdpid_service_after_delete`;
DELIMITER //
CREATE TRIGGER `sdpid_service_after_delete` AFTER DELETE ON `sdpid_service`
 FOR EACH ROW BEGIN
    INSERT INTO refresh_trigger
    SET table_name = 'sdpid_service',
        event = 'delete';
END
//
DELIMITER ;
DROP TRIGGER IF EXISTS `sdpid_service_after_insert`;
DELIMITER //
CREATE TRIGGER `sdpid_service_after_insert` AFTER INSERT ON `sdpid_service`
 FOR EACH ROW BEGIN
    INSERT INTO refresh_trigger
    SET table_name = 'sdpid_service',
        event = 'insert';
END
//
DELIMITER ;
DROP TRIGGER IF EXISTS `sdpid_service_after_update`;
DELIMITER //
CREATE TRIGGER `sdpid_service_after_update` AFTER UPDATE ON `sdpid_service`
 FOR EACH ROW BEGIN
    INSERT INTO refresh_trigger
    SET table_name = 'sdpid_service',
        event = 'update';
END
//
DELIMITER ;

-- --------------------------------------------------------

--
-- Table structure for table `service`
--

CREATE TABLE IF NOT EXISTS `service` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(1024) COLLATE utf8_bin NOT NULL,
  `description` varchar(4096) COLLATE utf8_bin NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=6 ;

--
-- Dumping data for table `service`
--

INSERT INTO `service` (`id`, `name`, `description`) VALUES
(1, 'SDP Controller', 'What it sounds like'),
(2, 'gate2 ssh', 'ssh service on gate2'),
(3, 'mail', 'mail server'),
(4, 'gate2.com', 'website');

--
-- Triggers `service`
--
DROP TRIGGER IF EXISTS `service_after_delete`;
DELIMITER //
CREATE TRIGGER `service_after_delete` AFTER DELETE ON `service`
 FOR EACH ROW BEGIN
    INSERT INTO refresh_trigger
    SET table_name = 'service',
        event = 'delete';
END
//
DELIMITER ;

-- --------------------------------------------------------

--
-- Table structure for table `service_gateway`
--

CREATE TABLE IF NOT EXISTS `service_gateway` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `service_id` int(11) NOT NULL,
  `gateway_sdpid` int(11) NOT NULL,
  `protocol` tinytext COLLATE utf8_bin NOT NULL COMMENT 'TCP, UDP',
  `port` int(10) unsigned NOT NULL,
  `nat_ip` varchar(128) COLLATE utf8_bin NOT NULL DEFAULT '' COMMENT '1.1.1.1   internal IP address',
  `nat_port` int(10) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `service_id` (`service_id`),
  KEY `gateway_sdpid` (`gateway_sdpid`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=5 ;

--
-- RELATIONS FOR TABLE `service_gateway`:
--   `service_id`
--       `service` -> `id`
--   `gateway_sdpid`
--       `sdpid` -> `sdpid`
--

--
-- Dumping data for table `service_gateway`
--

INSERT INTO `service_gateway` (`id`, `service_id`, `gateway_sdpid`, `protocol`, `port`, `nat_ip`, `nat_port`) VALUES
(1, 1, 222, 'TCP', 5000, '', 0),
(2, 2, 222, 'TCP', 22, '', 0),
(3, 3, 222, 'TCP', 25, '192.168.1.250', 54321),
(4, 4, 222, 'TCP', 80, '', 0);

--
-- Triggers `service_gateway`
--
DROP TRIGGER IF EXISTS `service_gateway_after_delete`;
DELIMITER //
CREATE TRIGGER `service_gateway_after_delete` AFTER DELETE ON `service_gateway`
 FOR EACH ROW BEGIN
    INSERT INTO refresh_trigger
    SET table_name = 'service_gateway',
        event = 'delete';
END
//
DELIMITER ;
DROP TRIGGER IF EXISTS `service_gateway_after_insert`;
DELIMITER //
CREATE TRIGGER `service_gateway_after_insert` AFTER INSERT ON `service_gateway`
 FOR EACH ROW BEGIN
    INSERT INTO refresh_trigger
    SET table_name = 'service_gateway',
        event = 'insert';
END
//
DELIMITER ;
DROP TRIGGER IF EXISTS `service_gateway_after_update`;
DELIMITER //
CREATE TRIGGER `service_gateway_after_update` AFTER UPDATE ON `service_gateway`
 FOR EACH ROW BEGIN
    INSERT INTO refresh_trigger
    SET table_name = 'service_gateway',
        event = 'update';
END
//
DELIMITER ;

-- --------------------------------------------------------

--
-- Table structure for table `user`
--

CREATE TABLE IF NOT EXISTS `user` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `last_name` varchar(128) COLLATE utf8_bin NOT NULL,
  `first_name` varchar(128) COLLATE utf8_bin NOT NULL,
  `country` varchar(128) COLLATE utf8_bin DEFAULT NULL,
  `state` varchar(128) COLLATE utf8_bin DEFAULT NULL,
  `locality` varchar(128) COLLATE utf8_bin DEFAULT NULL,
  `org` varchar(128) COLLATE utf8_bin DEFAULT NULL,
  `org_unit` varchar(128) COLLATE utf8_bin DEFAULT NULL,
  `alt_name` varchar(128) COLLATE utf8_bin DEFAULT NULL,
  `email` varchar(128) COLLATE utf8_bin NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=3 ;

--
-- Dumping data for table `user`
--

INSERT INTO `user` (`id`, `last_name`, `first_name`, `country`, `state`, `locality`, `org`, `org_unit`, `alt_name`, `email`) VALUES
(1, 'Last', 'First', '', '', '', '', '', '', 'email@email.com'),
(2, 'Otherlast', 'Otherfirst', 'US', 'Florida', 'Miami', 'Waverley Labs, LLC', 'R&D', NULL, 'email@email.com');

--
-- Triggers `user`
--
DROP TRIGGER IF EXISTS `user_after_delete`;
DELIMITER //
CREATE TRIGGER `user_after_delete` AFTER DELETE ON `user`
 FOR EACH ROW BEGIN
    INSERT INTO refresh_trigger
    SET table_name = 'user',
        event = 'delete';
END
//
DELIMITER ;

-- --------------------------------------------------------

--
-- Table structure for table `user_group`
--

CREATE TABLE IF NOT EXISTS `user_group` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `group_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  KEY `group_id` (`group_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=1 ;

--
-- RELATIONS FOR TABLE `user_group`:
--   `user_id`
--       `user` -> `id`
--   `group_id`
--       `group` -> `id`
--

--
-- Triggers `user_group`
--
DROP TRIGGER IF EXISTS `user_group_after_delete`;
DELIMITER //
CREATE TRIGGER `user_group_after_delete` AFTER DELETE ON `user_group`
 FOR EACH ROW BEGIN
    INSERT INTO refresh_trigger
    SET table_name = 'user_group',
        event = 'delete';
END
//
DELIMITER ;
DROP TRIGGER IF EXISTS `user_group_after_insert`;
DELIMITER //
CREATE TRIGGER `user_group_after_insert` AFTER INSERT ON `user_group`
 FOR EACH ROW BEGIN
    INSERT INTO refresh_trigger
    SET table_name = 'user_group',
        event = 'insert';
END
//
DELIMITER ;
DROP TRIGGER IF EXISTS `user_group_after_update`;
DELIMITER //
CREATE TRIGGER `user_group_after_update` AFTER UPDATE ON `user_group`
 FOR EACH ROW BEGIN
    INSERT INTO refresh_trigger
    SET table_name = 'user_group',
        event = 'update';
END
//
DELIMITER ;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `closed_connection`
--
ALTER TABLE `closed_connection`
  ADD CONSTRAINT `closed_connection_ibfk_1` FOREIGN KEY (`gateway_sdpid`) REFERENCES `sdpid` (`sdpid`) ON DELETE NO ACTION ON UPDATE CASCADE,
  ADD CONSTRAINT `closed_connection_ibfk_2` FOREIGN KEY (`client_sdpid`) REFERENCES `sdpid` (`sdpid`) ON DELETE NO ACTION ON UPDATE CASCADE;

--
-- Constraints for table `controller`
--
ALTER TABLE `controller`
  ADD CONSTRAINT `controller_ibfk_1` FOREIGN KEY (`sdpid`) REFERENCES `sdpid` (`sdpid`) ON UPDATE CASCADE,
  ADD CONSTRAINT `controller_ibfk_2` FOREIGN KEY (`service_id`) REFERENCES `service` (`id`) ON UPDATE CASCADE,
  ADD CONSTRAINT `controller_ibfk_3` FOREIGN KEY (`gateway_sdpid`) REFERENCES `sdpid` (`sdpid`) ON UPDATE CASCADE;

--
-- Constraints for table `gateway`
--
ALTER TABLE `gateway`
  ADD CONSTRAINT `gateway_ibfk_1` FOREIGN KEY (`sdpid`) REFERENCES `sdpid` (`sdpid`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `gateway_controller`
--
ALTER TABLE `gateway_controller`
  ADD CONSTRAINT `gateway_controller_ibfk_1` FOREIGN KEY (`gateway_sdpid`) REFERENCES `sdpid` (`sdpid`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `gateway_controller_ibfk_2` FOREIGN KEY (`controller_sdpid`) REFERENCES `sdpid` (`sdpid`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `group_service`
--
ALTER TABLE `group_service`
  ADD CONSTRAINT `group_service_ibfk_1` FOREIGN KEY (`group_id`) REFERENCES `group` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `group_service_ibfk_2` FOREIGN KEY (`service_id`) REFERENCES `service` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `open_connection`
--
ALTER TABLE `open_connection`
  ADD CONSTRAINT `open_connection_ibfk_1` FOREIGN KEY (`gateway_sdpid`) REFERENCES `sdpid` (`sdpid`) ON DELETE NO ACTION ON UPDATE CASCADE,
  ADD CONSTRAINT `open_connection_ibfk_2` FOREIGN KEY (`client_sdpid`) REFERENCES `sdpid` (`sdpid`) ON DELETE NO ACTION ON UPDATE CASCADE,
  ADD CONSTRAINT `open_connection_ibfk_3` FOREIGN KEY (`service_id`) REFERENCES `service` (`id`) ON DELETE NO ACTION ON UPDATE CASCADE;

--
-- Constraints for table `sdpid`
--
ALTER TABLE `sdpid`
  ADD CONSTRAINT `sdpid_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `user` (`id`) ON UPDATE CASCADE,
  ADD CONSTRAINT `sdpid_ibfk_2` FOREIGN KEY (`environment_id`) REFERENCES `environment` (`id`) ON UPDATE CASCADE;

--
-- Constraints for table `sdpid_service`
--
ALTER TABLE `sdpid_service`
  ADD CONSTRAINT `sdpid_service_ibfk_1` FOREIGN KEY (`sdpid`) REFERENCES `sdpid` (`sdpid`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `sdpid_service_ibfk_2` FOREIGN KEY (`service_id`) REFERENCES `service` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `service_gateway`
--
ALTER TABLE `service_gateway`
  ADD CONSTRAINT `service_gateway_ibfk_1` FOREIGN KEY (`service_id`) REFERENCES `service` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `service_gateway_ibfk_2` FOREIGN KEY (`gateway_sdpid`) REFERENCES `sdpid` (`sdpid`) ON UPDATE CASCADE;

--
-- Constraints for table `user_group`
--
ALTER TABLE `user_group`
  ADD CONSTRAINT `user_group_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `user` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `user_group_ibfk_2` FOREIGN KEY (`group_id`) REFERENCES `group` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;

