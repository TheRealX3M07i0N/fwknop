--
-- Database: `sdp_test`
--
USE `sdp_test`;

DELETE FROM `sdp_test`.`sdpid_service` 
WHERE `sdpid_service`.`sdpid` = 333 AND
      `sdpid_service`.`service_id` = 1;
