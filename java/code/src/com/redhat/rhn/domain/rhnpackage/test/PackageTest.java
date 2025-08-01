/*
 * Copyright (c) 2009--2017 Red Hat, Inc.
 *
 * This software is licensed to you under the GNU General Public License,
 * version 2 (GPLv2). There is NO WARRANTY for this software, express or
 * implied, including the implied warranties of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
 * along with this software; if not, see
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
 *
 * Red Hat trademarks are not licensed under GPLv2. No permission is
 * granted to use or replicate Red Hat trademarks that are incorporated
 * in this software or its documentation.
 */
package com.redhat.rhn.domain.rhnpackage.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.redhat.rhn.common.db.datasource.ModeFactory;
import com.redhat.rhn.common.db.datasource.WriteMode;
import com.redhat.rhn.common.hibernate.HibernateFactory;
import com.redhat.rhn.common.util.SHA256Crypt;
import com.redhat.rhn.domain.channel.Channel;
import com.redhat.rhn.domain.common.ChecksumFactory;
import com.redhat.rhn.domain.org.Org;
import com.redhat.rhn.domain.rhnpackage.Package;
import com.redhat.rhn.domain.rhnpackage.PackageArch;
import com.redhat.rhn.domain.rhnpackage.PackageCapability;
import com.redhat.rhn.domain.rhnpackage.PackageEvr;
import com.redhat.rhn.domain.rhnpackage.PackageFactory;
import com.redhat.rhn.domain.rhnpackage.PackageFile;
import com.redhat.rhn.domain.rhnpackage.PackageGroup;
import com.redhat.rhn.domain.rhnpackage.PackageName;
import com.redhat.rhn.domain.rhnpackage.PackageSource;
import com.redhat.rhn.domain.rhnpackage.PackageType;
import com.redhat.rhn.domain.rpm.SourceRpm;
import com.redhat.rhn.domain.rpm.test.SourceRpmTest;
import com.redhat.rhn.domain.user.User;
import com.redhat.rhn.manager.rhnpackage.test.PackageManagerTest;
import com.redhat.rhn.testing.BaseTestCaseWithUser;
import com.redhat.rhn.testing.PackageTestUtils;
import com.redhat.rhn.testing.TestUtils;
import com.redhat.rhn.testing.UserTestUtils;

import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * PackageTest
 */
public class PackageTest extends BaseTestCaseWithUser {

    @Test
    public void testIsType() {
        Package pkgRpm = PackageTest.createTestPackage(user.getOrg(),
                PackageFactory.lookupPackageArchByLabel("x86_64"));

        Package pkgDeb = PackageTest.createTestPackage(user.getOrg(),
                PackageFactory.lookupPackageArchByLabel("amd64-deb"));

        assertTrue(pkgRpm.isTypeRpm());
        assertFalse(pkgRpm.isTypeDeb());

        assertFalse(pkgDeb.isTypeRpm());
        assertTrue(pkgDeb.isTypeDeb());
    }

    @Test
    public void testPackage() {
        Package pkg = createTestPackage(user.getOrg());
        assertNotNull(pkg);
        //make sure we got written to the db
        assertNotNull(pkg.getId());
        TestUtils.flushAndEvict(pkg);

        Package lookup = PackageFactory.lookupByIdAndOrg(pkg.getId(), pkg.getOrg());
        assertNotNull(lookup);
        assertNotNull(lookup.getBuildTime());
    }

    @Test
    public void testFile() {
        User user = UserTestUtils.findNewUser("testUser",
                "testOrg" + this.getClass().getSimpleName());
        Package pkg = createTestPackage(user.getOrg());
        assertNotNull(pkg);

        String filename = "foo-2.31-4-i386.rpm";
        String path = "/foo/bar/foos/";

        pkg.setPath(path + filename);
        assertEquals(filename, pkg.getFile());

        pkg.setPath(filename);
        assertEquals(filename, pkg.getFile());

        pkg.setPath("");
        assertNull(pkg.getFile());

        pkg.setPath(null);
        assertNull(pkg.getFile());

        pkg.setPath("////foo//b///foo/");
        assertEquals("foo", pkg.getFile());
    }

    public static Package createTestPackage(Org org, PackageArch arch) {
        Package p = new Package();
        populateTestPackage(p, org, arch);

        TestUtils.saveAndFlush(p);

        return p;
    }

    public static Package createTestPackage(Org org) {
        Package p = populateTestPackage(new Package(), org);
        TestUtils.saveAndFlush(p);
        return p;
    }

    public static Package createTestPackage(Org org, String packageName) {
        Package p = populateTestPackage(new Package(), packageName, org);
        TestUtils.saveAndFlush(p);
        return p;
    }

    public static Package populateTestPackage(Package p, Org org, PackageName name, PackageEvr evr, PackageArch arch) {
        PackageGroup pgroup = PackageGroupTest.createTestPackageGroup();
        SourceRpm srpm = SourceRpmTest.createTestSourceRpm();

        p.setRpmVersion("foo");
        p.setDescription("RHN-JAVA Package Test");
        p.setSummary("Created by RHN-JAVA unit tests. Please disregard.");
        p.setPackageSize(42L);
        p.setPayloadSize(42L);
        p.setBuildHost("foo2");
        p.setBuildTime(new Date());
        p.setChecksum(ChecksumFactory.safeCreate(
                SHA256Crypt.sha256Hex(TestUtils.randomString()), "sha256"));
        p.setVendor("Rhn-Java");
        p.setPayloadFormat("testpayloadformat");
        p.setCompat(0L);
        p.setPath(SHA256Crypt.sha256Hex(TestUtils.randomString()));
        p.setHeaderSignature("Rhn-Java Unit Test");
        p.setCopyright("Red Hat - RHN - 2005");
        p.setCookie("Chocolate Chip");
        p.setCreated(new Date());
        p.setLastModified(new Date());

        p.setOrg(org);
        p.setPackageName(name);
        p.setPackageEvr(evr);
        p.setPackageGroup(pgroup);
        p.setSourceRpm(srpm);
        p.setPackageArch(arch);

        p.getPackageFiles().add(createTestPackageFile(p));
        p.getPackageFiles().add(createTestPackageFile(p));

        HibernateFactory.getSession().save(createTestPackageSource(srpm, org));
        return p;
    }

    public static Package populateTestPackage(Package p, Org org, PackageArch parch) {
        PackageName pname = PackageNameTest.createTestPackageName();
        return populateTestPackage(p, org, parch, pname);
    }

    private static Package populateTestPackage(Package p, Org org, PackageArch parch, PackageName pname) {
        PackageEvr pevr = PackageEvrFactoryTest.createTestPackageEvr(parch.getArchType().getPackageType());
        return populateTestPackage(p, org, pname, pevr, parch);
    }

    public static Package populateTestPackage(Package p, Org org) {
        PackageArch parch = (PackageArch) TestUtils.lookupFromCacheByLabel("noarch", "PackageArch.findByLabel");
        return populateTestPackage(p, org, parch);
    }

    public static Package populateTestPackage(Package p, String packageName, Org org) {
        PackageArch parch = (PackageArch) TestUtils.lookupFromCacheByLabel("noarch", "PackageArch.findByLabel");
        return populateTestPackage(p, org, parch, PackageNameTest.createTestPackageName(packageName));
    }
    public static PackageSource createTestPackageSource(SourceRpm rpm, Org org) {

        PackageSource source = new PackageSource();

        String string = "dkfjdkjf";
        Date date = new Date();

        try {
            source.setBuildHost(string);
            source.setBuildTime(date);
            source.setCookie(string);
            source.setCreated(date);
            source.setChecksum(ChecksumFactory.safeCreate(string, "md5"));
            source.setOrg(org);
            source.setPackageGroup(PackageGroupTest.createTestPackageGroup());
            source.setPackageSize(343L);
            source.setPath(string);
            source.setPayloadSize(343L);
            source.setRpmVersion(string);
            source.setSigchecksum(ChecksumFactory.safeCreate(string, "md5"));
            source.setSourceRpm(rpm);
            source.setVendor(string);
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        return source;
    }


    public static PackageFile createTestPackageFile(Package pack) {
        PackageFile file = new PackageFile();
        PackageCapability cap = new PackageCapability();
        cap.setName(TestUtils.randomString());
        cap.setVersion(TestUtils.randomString());
        cap.setCreated(new Date());
        cap = TestUtils.saveAndReload(cap);

        file.setCapability(cap);
        file.setPack(pack);
        file.setDevice(234L);
        file.setFileMode(3434L);
        file.setFileSize(3434L);
        file.setFlags(343L);
        file.setGroupname("herjej");
        file.setInode(343L);
        file.setLang("eng");
        file.setLinkTo("dkfjdkfj");
        file.setChecksum(ChecksumFactory.safeCreate("kfdjfkd", "md5"));
        file.setModified(new Date());
        file.setMtime(new Date());
        file.setRdev(3434L);
        file.setUsername("dkfjdk");
        file.setCreated(new Date());
        file.setVerifyFlags(34434L);

        return file;
    }


    public static void addPackageToChannelNewestPackage(Package p, Channel c) {
        /*
       INSERT INTO rhnChannelNewestPackage(CHANNEL_ID, NAME_ID, EVR_ID,
         PACKAGE_ARCH_ID, PACKGE_ID)
         VALUES(:channel_id, :name_id, :evr_id, :package_arch_id, :packge_id)
         */

        WriteMode m =
            ModeFactory.
            getWriteMode("test_queries", "insert_into_rhnChannelNewestPackage");
        Map<String, Object> params = new HashMap<>();
        params.put("channel_id", c.getId());
        params.put("name_id", p.getPackageName().getId());
        params.put("evr_id", p.getPackageEvr().getId());
        params.put("package_arch_id", p.getPackageArch().getId());
        params.put("packge_id", p.getId());

        m.executeUpdate(params);

        // insert_into_rhnChannelPackage
        WriteMode cp =
            ModeFactory.
            getWriteMode("test_queries", "insert_into_rhnChannelPackage");
        params = new HashMap<>();
        params.put("channel_id", c.getId());
        params.put("packge_id", p.getId());

        cp.executeUpdate(params);
    }

    @Test
    public void testGetNevraWithEpoch() {
        Package pkg = createTestPackage(user.getOrg());
        PackageEvr evr = PackageEvrFactoryTest.createTestPackageEvr("1", "2", "3", PackageType.RPM);
        pkg.setPackageEvr(evr);

        String expectedNevra = pkg.getPackageName().getName() + "-1:2-3." + pkg.getPackageArch().getLabel();
        assertEquals(expectedNevra, pkg.getNevraWithEpoch());
        // Following two methods must return the same result if an epoch exists
        assertEquals(pkg.getNameEvra(), pkg.getNevraWithEpoch());

        evr = PackageEvrFactoryTest.createTestPackageEvr(null, "2", "3", PackageType.RPM);
        pkg.setPackageEvr(evr);

        expectedNevra = pkg.getPackageName().getName() + "-0:2-3." + pkg.getPackageArch().getLabel();
        assertEquals(expectedNevra, pkg.getNevraWithEpoch());
        assertNotEquals(pkg.getNameEvra(), pkg.getNevraWithEpoch());
    }

    @Test
    public void testIsInChannel() {
        // TODO make this work on sate
    }

    @Test
    public void testGetExtraTag() {
        Package pkg = createTestPackage(user.getOrg());
        pkg.getExtraTags().put(PackageManagerTest.createExtraTagKey("mytag"), "myvalue");

        assertEquals("myvalue", pkg.getExtraTag("mytag"));
        assertNull(pkg.getExtraTag("doesnotexist"));
    }

    @Test
    public void testRetrievePtfInformation() {
        Package masterPtfPackage = PackageTestUtils.createPtfMaster("123456", "1", user.getOrg());

        assertTrue(masterPtfPackage.isMasterPtfPackage());
        assertFalse(masterPtfPackage.isPartOfPtf());

        Package ptfPackage = PackageTestUtils.createPtfPackage("123456", "1", user.getOrg());

        assertFalse(ptfPackage.isMasterPtfPackage());
        assertTrue(ptfPackage.isPartOfPtf());
    }

}
