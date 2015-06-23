/*
 * Licensed to the University of California, Berkeley under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The ASF licenses this file to You under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License. You may obtain a
 * copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package tachyon.worker;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;

import org.apache.thrift.TException;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import tachyon.Constants;
import tachyon.TachyonURI;
import tachyon.TestUtils;
import tachyon.client.TachyonFS;
import tachyon.client.TachyonFSTestUtils;
import tachyon.client.WriteType;
import tachyon.conf.TachyonConf;
import tachyon.master.LocalTachyonCluster;
import tachyon.master.MasterInfo;
import tachyon.thrift.ClientFileInfo;
import tachyon.thrift.FileDoesNotExistException;
import tachyon.thrift.InvalidPathException;
import tachyon.thrift.OutOfSpaceException;
import tachyon.underfs.UnderFileSystem;
import tachyon.util.CommonUtils;
import tachyon.worker.block.BlockServiceHandler;
import tachyon.worker.block.io.BlockWriter;

/**
 * Integration tests for tachyon.BlockServiceHandler
 */
public class BlockServiceHandlerIntegrationTest {
  private static final long WORKER_CAPACITY_BYTES = 10000;
  private static final long USER_ID = 1L;
  private static final int USER_QUOTA_UNIT_BYTES = 100;

  private LocalTachyonCluster mLocalTachyonCluster = null;
  private MasterInfo mMasterInfo = null;
  private BlockServiceHandler mWorkerServiceHandler = null;
  private TachyonFS mTfs = null;
  private TachyonConf mMasterTachyonConf;
  private TachyonConf mWorkerTachyonConf;

  @After
  public final void after() throws Exception {
    mLocalTachyonCluster.stop();
  }

  @Before
  public final void before() throws IOException {
    mLocalTachyonCluster = new LocalTachyonCluster(WORKER_CAPACITY_BYTES, USER_QUOTA_UNIT_BYTES,
        Constants.GB);
    mLocalTachyonCluster.start();
    mWorkerServiceHandler = mLocalTachyonCluster.getWorker().getWorkerServiceHandler();
    mMasterInfo = mLocalTachyonCluster.getMasterInfo();
    mTfs = mLocalTachyonCluster.getClient();
    mMasterTachyonConf = mLocalTachyonCluster.getMasterTachyonConf();
    mWorkerTachyonConf = mLocalTachyonCluster.getWorkerTachyonConf();
  }

  // Tests that caching a block successfully persists the block if the block exists
  @Test
  public void cacheBlockTest() throws Exception {
    final int fileId = mTfs.createFile(new TachyonURI("/testFile"));
    final long blockId0 = mTfs.getBlockId(fileId, 0);
    final long blockId1 = mTfs.getBlockId(fileId, 1);
    final long blockSize = WORKER_CAPACITY_BYTES / 10;

    String filename = mWorkerServiceHandler.requestBlockLocation(USER_ID, blockId0, blockSize);
    createBlockFile(filename, (int) blockSize);
    mWorkerServiceHandler.cacheBlock(USER_ID, blockId0);

    // The master should be immediately updated with the persisted block
    Assert.assertEquals(blockSize, mMasterInfo.getUsedBytes());

    // Attempting to cache a non existant block should throw an exception
    Exception exception = null;
    try {
      mWorkerServiceHandler.cacheBlock(USER_ID, blockId1);
    } catch (TException e) {
      exception = e;
    }
    Assert.assertNotNull(exception);
  }

  // Tests that cancelling a block will remove the temporary file
  @Test
  public void cancelBlockTest() throws Exception {
    final int fileId = mTfs.createFile(new TachyonURI("/testFile"));
    final long blockId = mTfs.getBlockId(fileId, 0);
    final long blockSize = WORKER_CAPACITY_BYTES / 2;

    String filename = mWorkerServiceHandler.requestBlockLocation(USER_ID, blockId, blockSize);
    createBlockFile(filename, (int) blockSize);
    mWorkerServiceHandler.cancelBlock(USER_ID, blockId);

    // The block should not exist after being cancelled
    Assert.assertFalse(new File(filename).exists());

    // The master should not have recorded any used space after the block is cancelled
    waitForHeartbeat();
    Assert.assertEquals(0, mMasterInfo.getUsedBytes());
  }

  @Test
  public void evictionTest() throws Exception {
    int fileId1 =
        TachyonFSTestUtils.createByteFile(mTfs, "/file1", WriteType.MUST_CACHE,
            (int) WORKER_CAPACITY_BYTES / 3);
    Assert.assertTrue(fileId1 >= 0);
    ClientFileInfo fileInfo1 = mMasterInfo.getClientFileInfo(new TachyonURI("/file1"));
    Assert.assertEquals(100, fileInfo1.inMemoryPercentage);
    int fileId2 =
        TachyonFSTestUtils.createByteFile(mTfs, "/file2", WriteType.MUST_CACHE,
            (int) WORKER_CAPACITY_BYTES / 3);
    Assert.assertTrue(fileId2 >= 0);
    fileInfo1 = mMasterInfo.getClientFileInfo(new TachyonURI("/file1"));
    ClientFileInfo fileInfo2 = mMasterInfo.getClientFileInfo(new TachyonURI("/file2"));
    Assert.assertEquals(100, fileInfo1.inMemoryPercentage);
    Assert.assertEquals(100, fileInfo2.inMemoryPercentage);
    int fileId3 =
        TachyonFSTestUtils.createByteFile(mTfs, "/file3", WriteType.MUST_CACHE,
            (int) WORKER_CAPACITY_BYTES / 2);

    CommonUtils.sleepMs(null,
        TestUtils.getToMasterHeartBeatIntervalMs(mWorkerTachyonConf) * 2 + 10);

    fileInfo1 = mMasterInfo.getClientFileInfo(new TachyonURI("/file1"));
    fileInfo2 = mMasterInfo.getClientFileInfo(new TachyonURI("/file2"));
    ClientFileInfo fileInfo3 = mMasterInfo.getClientFileInfo(new TachyonURI("/file3"));
    Assert.assertTrue(fileId3 >= 0);
    Assert.assertEquals(0, fileInfo1.inMemoryPercentage);
    Assert.assertEquals(100, fileInfo2.inMemoryPercentage);
    Assert.assertEquals(100, fileInfo3.inMemoryPercentage);
  }

  @Test
  public void requestSpaceTest() throws Exception {
    final long userId = 1L;
    final long blockId1 = 12345L;
    final long blockId2 = 12346L;
    String filename = mWorkerServiceHandler.requestBlockLocation(userId, blockId1,
        WORKER_CAPACITY_BYTES / 10L);
    Assert.assertTrue(filename != null);
    boolean result =
        mWorkerServiceHandler.requestSpace(userId, blockId1, WORKER_CAPACITY_BYTES / 10L);
    Assert.assertEquals(true, result);
    result = mWorkerServiceHandler.requestSpace(userId, blockId1, WORKER_CAPACITY_BYTES);
    Assert.assertEquals(false, result);
    Exception exception = null;
    Assert.assertFalse(mWorkerServiceHandler.requestSpace(userId, blockId2,
        WORKER_CAPACITY_BYTES / 10L));
    try {
      mWorkerServiceHandler.requestBlockLocation(userId, blockId2, WORKER_CAPACITY_BYTES + 1);
    } catch (OutOfSpaceException e) {
      exception = e;
    }
    Assert.assertEquals(new OutOfSpaceException(String.format("Failed to allocate "
        + (WORKER_CAPACITY_BYTES + 1) + " for user " + userId)), exception);
  }

  @Test
  public void totalOverCapacityRequestSpaceTest() throws Exception {
    final long userId1 = 1L;
    final long blockId1 = 12345L;
    final long userId2 = 2L;
    final long blockId2 = 23456L;
    String filePath1 = mWorkerServiceHandler.requestBlockLocation(userId1, blockId1,
        WORKER_CAPACITY_BYTES / 2);
    Assert.assertTrue(filePath1 != null);
    String filePath2 = mWorkerServiceHandler.requestBlockLocation(userId2, blockId2,
        WORKER_CAPACITY_BYTES / 2);
    Assert.assertTrue(filePath2 != null);

    Assert.assertFalse(mWorkerServiceHandler.requestSpace(userId1, blockId1,
        WORKER_CAPACITY_BYTES / 2));
    Assert.assertFalse(mWorkerServiceHandler.requestSpace(userId2, blockId2,
        WORKER_CAPACITY_BYTES / 2));
  }

  private void createBlockFile(String filename, int len) throws IOException, InvalidPathException {
    UnderFileSystem ufs = UnderFileSystem.get(filename, mMasterTachyonConf);
    ufs.mkdirs(CommonUtils.getParent(filename), true);
    OutputStream out = ufs.create(filename);
    out.write(TestUtils.getIncreasingByteArray(len), 0, len);
    out.close();
  }

  // Sleeps for a duration so that the worker heartbeat to master can be processed
  private void waitForHeartbeat() {
    CommonUtils.sleepMs(null, TestUtils.getToMasterHeartBeatIntervalMs(mWorkerTachyonConf) * 3);
  }
}