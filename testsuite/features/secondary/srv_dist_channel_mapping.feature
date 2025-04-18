# Copyright (c) 2022-2025 SUSE LLC
# Licensed under the terms of the MIT license.

Feature: Distribution Channel Mapping

  Scenario: Log in as org admin user
    Given I am authorized

  Scenario: Check if Distribution Channel Mapping page exists
    When I follow the left menu "Software > Distribution Channel Mapping"
    Then I should see a "Distribution Channel Mapping" text
    And I should see a "Channel List" link in the left menu
    And I should see a "Package Search" link in the left menu
    And I should see a "Manage" link in the left menu
    And I should see a "Distribution Channel Mapping" link in the left menu
    And I should see a "Create Distribution Channel Mapping" link
    And I should see a "No distribution channel mappings currently exist." text in the content area

@scc_credentials
@susemanager
  Scenario: Create new map for x86_64 SUSE clients
    When I follow the left menu "Software > Distribution Channel Mapping"
    And I follow "Create Distribution Channel Mapping"
    Then I should see a "Create Distribution Channel Map" text
    When I enter "SUSE Linux Enterprise Server 15 SP 4" as "os"
    And I enter "15.5" as "release"
    And I select "x86_64" from "architecture"
    And I select "SLE-Product-SLES15-SP4-Pool for x86_64" from "channel_label"
    And I click on "Create Mapping"
    Then I should see a "SUSE Linux Enterprise Server 15 SP 4" link in the content area

@scc_credentials
@uyuni
  Scenario: Create new map for x86_64 openSUSE clients
    When I follow the left menu "Software > Distribution Channel Mapping"
    And I follow "Create Distribution Channel Mapping"
    Then I should see a "Create Distribution Channel Map" text
    When I enter "openSUSE Leap 15.6" as "os"
    And I enter "15.6" as "release"
    And I select "x86_64" from "architecture"
    And I select "openSUSE Leap 15.6 (x86_64)" from "channel_label"
    And I click on "Create Mapping"
    Then I should see a "openSUSE Leap 15.6" link in the content area

@deblike_minion
  Scenario: Create new map for amd64 Ubuntu clients with test base channel
    When I follow the left menu "Software > Distribution Channel Mapping"
    And I follow "Create Distribution Channel Mapping"
    Then I should see a "Create Distribution Channel Map" text
    When I enter "Ubuntu 24.04" as "os"
    And I enter "24.04" as "release"
    And I select "AMD64 Debian" from "architecture"
    And I select "Fake-Base-Channel-Debian-like" from "channel_label"
    And I click on "Create Mapping"
    Then I should see a "Ubuntu 24.04" link in the content area

@scc_credentials
  Scenario: Create new map for iSeries SUSE clients using test channel
    When I follow the left menu "Software > Distribution Channel Mapping"
    And I follow "Create Distribution Channel Mapping"
    Then I should see a "Create Distribution Channel Map" text
    When I enter "SUSE Linux Enterprise Server 15 SP 4 iSeries" as "os"
    And I enter "15.5" as "release"
    And I select "iSeries" from "architecture"
    And I select "Fake-Base-Channel-i586" from "channel_label"
    And I click on "Create Mapping"
    Then I should see a "SUSE Linux Enterprise Server 15 SP 4 iSeries" link in the content area

@scc_credentials
@susemanager
  Scenario: Update map for x86_64 SUSE clients using test-x86_64 channel
    When I follow the left menu "Software > Distribution Channel Mapping"
    Then I should see the text "SUSE Linux Enterprise Server 15 SP 4" in the Operating System field
    And I should see the text "x86_64" in the Architecture field
    And I should see the text "sle-product-sles15-sp4-pool-x86_64" in the Channel Label field
    When I follow "SUSE Linux Enterprise Server 15 SP 4"
    Then I should see a "Update Distribution Channel Map" text
    When I enter "SUSE Linux Enterprise Server 15 SP 4 modified" as "os"
    And I select "SLE-Product-SLES15-SP4-Pool for x86_64" from "channel_label"
    And I click on "Update Mapping"
    Then I should see the text "SUSE Linux Enterprise Server 15 SP 4 modified" in the Operating System field
    And I should see the text "sle-product-sles15-sp4-pool-x86_64" in the Channel Label field

@scc_credentials
@uyuni
  Scenario: Update map for x86_64 openSUSE clients using test-x86_64 channel
    When I follow the left menu "Software > Distribution Channel Mapping"
    Then I should see the text "openSUSE Leap 15.6" in the Operating System field
    And I should see the text "x86_64" in the Architecture field
    And I should see the text "opensuse_leap15_6-x86_64" in the Channel Label field
    When I follow "openSUSE Leap 15.6"
    Then I should see a "Update Distribution Channel Map" text
    When I enter "openSUSE Leap 15.6 modified" as "os"
    And I select "openSUSE Leap 15.6 (x86_64)" from "channel_label"
    And I click on "Update Mapping"
    Then I should see the text "openSUSE Leap 15.6 modified" in the Operating System field
    And I should see the text "opensuse_leap15_6-x86_64" in the Channel Label field

@deblike_minion
  Scenario: Update map for amd64 Ubuntu clients using test base channel
    When I follow the left menu "Software > Distribution Channel Mapping"
    Then I should see the text "Ubuntu 24.04" in the Operating System field
    And I should see the text "AMD64 Debian" in the Architecture field
    And I should see the text "fake-base-channel-debian-like" in the Channel Label field
    When I follow "Ubuntu 24.04"
    And I enter "Ubuntu 24.04 modified" as "os"
    And I click on "Update Mapping"
    Then I should see the text "Ubuntu 24.04 modified" in the Operating System field

@scc_credentials
  Scenario: Update map for IA-32 SUSE clients using amd deb test channel
    When I follow the left menu "Software > Distribution Channel Mapping"
    Then I should see the text "SUSE Linux Enterprise Server 15 SP 4 iSeries" in the Operating System field
    And I should see the text "iSeries" in the Architecture field
    And I should see the text "fake-base-channel-i586" in the Channel Label field
    When I follow "SUSE Linux Enterprise Server 15 SP 4 iSeries"
    And I enter "SUSE Linux Enterprise Server 15 SP 4 iSeries modified" as "os"
    And I select "Fake-Base-Channel-Debian-like" from "channel_label"
    And I click on "Update Mapping"
    Then I should see the text "SUSE Linux Enterprise Server 15 SP 4 iSeries modified" in the Operating System field
    And I should see the text "fake-base-channel-debian-like" in the Channel Label field

@scc_credentials
@susemanager
  Scenario: Cleanup: delete the map created for x68_64 SUSE clients
    When I follow the left menu "Software > Distribution Channel Mapping"
    Then I should see the text "SUSE Linux Enterprise Server 15 SP 4 modified" in the Operating System field
    And I should see the text "x86_64" in the Architecture field
    When I follow "SUSE Linux Enterprise Server 15 SP 4 modified"
    Then I should see a "Update Distribution Channel Map" text
    And I should see a "Delete Distribution Channel" link
    When I follow "Delete Distribution Channel Mapping"
    Then I should see a "Delete Distribution Channel Map" text
    When I click on "Delete Mapping"
    Then I should not see a "SUSE Linux Enterprise Server 15 SP 4 modified" link

@scc_credentials
@uyuni
  Scenario: Cleanup: delete the map created for x68_64 openSUSE clients
    When I follow the left menu "Software > Distribution Channel Mapping"
    Then I should see the text "openSUSE Leap 15.6 modified" in the Operating System field
    And I should see the text "x86_64" in the Architecture field
    When I follow "openSUSE Leap 15.6 modified"
    Then I should see a "Update Distribution Channel Map" text
    And I should see a "Delete Distribution Channel" link
    When I follow "Delete Distribution Channel Mapping"
    Then I should see a "Delete Distribution Channel Map" text
    When I click on "Delete Mapping"
    Then I should not see a "openSUSE Leap 15.6 modified" link

@deblike_minion
  Scenario: Cleanup: delete the map created for amd64 Ubuntu clients
    When I follow the left menu "Software > Distribution Channel Mapping"
    Then I should see the text "Ubuntu 24.04 modified" in the Operating System field
    And I should see the text "AMD64 Debian" in the Architecture field
    When I follow "Ubuntu 24.04 modified"
    Then I should see a "Update Distribution Channel Map" text
    And I should see a "Delete Distribution Channel" link
    When I follow "Delete Distribution Channel Mapping"
    Then I should see a "Delete Distribution Channel Map" text
    When I click on "Delete Mapping"
    Then I should not see a "Ubuntu 24.04 modified" link

@scc_credentials
  Scenario: Cleanup: delete the map created for i586 clients
    When I follow the left menu "Software > Distribution Channel Mapping"
    Then I should see the text "SUSE Linux Enterprise Server 15 SP 4 iSeries modified" in the Operating System field
    And I should see the text "x86_64" in the Architecture field
    When I follow "SUSE Linux Enterprise Server 15 SP 4 iSeries modified"
    Then I should see a "Update Distribution Channel Map" text
    And I should see a "Delete Distribution Channel" link
    When I follow "Delete Distribution Channel Mapping"
    Then I should see a "Delete Distribution Channel Map" text
    When I click on "Delete Mapping"
    Then I should not see a "SUSE Linux Enterprise Server 15 SP 4 iSeries modified" link

  Scenario: Sanity check whether the page is in its default state
    When I follow the left menu "Software > Distribution Channel Mapping"
    Then I should see a "Distribution Channel Mapping" text
    And I should see a "No distribution channel mappings currently exist." text in the content area
