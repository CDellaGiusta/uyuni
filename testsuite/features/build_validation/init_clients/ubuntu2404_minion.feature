# Copyright (c) 2024 SUSE LLC
# Licensed under the terms of the MIT license.
#
#  1) bootstrap a new Ubuntu minion
#  2) subscribe it to a base channel for testing

@ubuntu2404_minion
Feature: Bootstrap a Ubuntu 24.04 Salt minion

  Scenario: Clean up sumaform leftovers on a Ubuntu 24.04 minion
    When I perform a full salt minion cleanup on "ubuntu2404_minion"

  Scenario: Log in as admin user
    Given I am authorized for the "Admin" section

  Scenario: Bootstrap a Ubuntu 24.04 minion
    When I follow the left menu "Systems > Bootstrapping"
    Then I should see a "Bootstrap Minions" text
    When I enter the hostname of "ubuntu2404_minion" as "hostname"
    And I enter "root" as "user"
    And I enter "linux" as "password"
    And I enter "22" as "port"
    And I enter "linux" as "password"
    And I select "1-ubuntu2404_minion_key" from "activationKeys"
    And I select the hostname of "proxy" from "proxies" if present
    And I click on "Bootstrap"
    And I wait until I see "Bootstrap process initiated." text
    And I wait until onboarding is completed for "ubuntu2404_minion"

@proxy
  Scenario: Check connection from Ubuntu 24.04 minion to proxy
    Given I am on the Systems overview page of this "ubuntu2404_minion"
    When I follow "Details" in the content area
    And I follow "Connection" in the content area
    Then I should see "proxy" short hostname

@proxy
  Scenario: Check registration on proxy of Ubuntu 24.04 minion
    Given I am on the Systems overview page of this "proxy"
    When I follow "Details" in the content area
    And I follow "Proxy" in the content area
    Then I should see "ubuntu2404_minion" hostname

  Scenario: Check events history for failures on Ubuntu 24.04 minion
    Given I am on the Systems overview page of this "ubuntu2404_minion"
    Then I check for failed events on history event page

  Scenario: Enable Universe repository on Ubuntu 24.04 minion
    When I enable Debian-like "universe" repository on "ubuntu2404_minion"
    And I refresh the metadata for "ubuntu2404_minion"
